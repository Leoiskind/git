import sys
import os
import zlib
import hashlib

import urllib.request
import struct

def read_object(sha):
    """Read and decompress a Git object."""
    path = f".git/objects/{sha[:2]}/{sha[2:]}"
    with open(path, "rb") as f:
        compressed = f.read()
    decompressed = zlib.decompress(compressed)
    null_idx = decompressed.find(b"\x00")
    header = decompressed[:null_idx].decode()
    content = decompressed[null_idx + 1 :]
    obj_type = header.split()[0]
    return obj_type, content

def hash_object(data, obj_type="blob"):
    """
    Computes the hash of a Git object and writes it to the object database.
    Returns the 40-character SHA-1 hash.
    """
    header = f"{obj_type} {len(data)}\x00".encode("utf-8")
    full_data = header + data
    
    sha1 = hashlib.sha1(full_data).hexdigest()
    
    # Write the object to the .git/objects directory
    obj_dir = f".git/objects/{sha1[:2]}"
    obj_file = f"{obj_dir}/{sha1[2:]}"
    
    os.makedirs(obj_dir, exist_ok=True)
    with open(obj_file, "wb") as f:
        f.write(zlib.compress(full_data))
        
    return sha1 # Return the 40-char hash

def parse_pkt_line(data):
    """Parse Git pkt-line format."""
    lines = []
    offset = 0

    while offset < len(data):
        if offset + 4 > len(data):
            break

        length_hex = data[offset : offset + 4].decode("ascii")

        if length_hex == "0000":
            lines.append(None)  # Flush packet
            offset += 4
        else:
            length = int(length_hex, 16)
            if length < 4:
                break
            line_data = data[offset + 4 : offset + length]
            lines.append(line_data)
            offset += length

    return lines

def parse_sideband_data(data):
    """Parse side-band multiplexed data and extract packfile."""
    result = bytearray()
    offset = 0

    while offset < len(data):
        if offset + 4 > len(data):
            break

        # Read pkt-line length
        length_hex = data[offset : offset + 4]
        try:
            length = int(length_hex, 16)
        except ValueError:
            break

        if length == 0:
            # Flush packet
            offset += 4
            continue

        if length < 4 or offset + length > len(data):
            break

        # Get packet payload
        payload = data[offset + 4 : offset + length]

        if len(payload) > 0:
            band = payload[0]
            packet_data = payload[1:]

            if band == 1:
                # Band 1: packfile data
                result.extend(packet_data)
            elif band == 2:
                # Band 2: progress messages
                print(
                    packet_data.decode("utf-8", errors="ignore").strip(),
                    file=sys.stderr,
                )
            elif band == 3:
                # Band 3: error messages
                print(
                    "Error from server:",
                    packet_data.decode("utf-8", errors="ignore").strip(),
                    file=sys.stderr,
                )

        offset += length

    return bytes(result)

def unpack_object(data, offset, objects_by_offset):
    """Unpack a single object from the packfile."""
    start_offset = offset
    obj_type, size, offset = read_size_encoding(data, offset)

    # Type constants
    OBJ_COMMIT = 1
    OBJ_TREE = 2
    OBJ_BLOB = 3
    OBJ_TAG = 4
    OBJ_OFS_DELTA = 6
    OBJ_REF_DELTA = 7

    type_map = {
        OBJ_COMMIT: "commit",
        OBJ_TREE: "tree",
        OBJ_BLOB: "blob",
        OBJ_TAG: "tag",
    }

    if obj_type == OBJ_OFS_DELTA:
        # Read negative offset
        neg_offset = data[offset] & 0x7F
        offset += 1
        while data[offset - 1] & 0x80:
            neg_offset = ((neg_offset + 1) << 7) | (data[offset] & 0x7F)
            offset += 1

        base_offset = start_offset - neg_offset
        base_type, base_data = objects_by_offset[base_offset]

        # Decompress delta data
        decompressor = zlib.decompressobj()
        delta_data = decompressor.decompress(data[offset:])

        # Apply delta
        content = apply_delta(base_data, delta_data)
        offset += len(data[offset:]) - len(decompressor.unused_data)
        obj_type_name = base_type

    elif obj_type == OBJ_REF_DELTA:
        # Read base object SHA (20 bytes)
        base_sha = data[offset : offset + 20]
        offset += 20

        # Find base object
        base_sha_hex = base_sha.hex()
        base_type, base_data = read_object(base_sha_hex)

        # Decompress delta data
        decompressor = zlib.decompressobj()
        delta_data = decompressor.decompress(data[offset:])

        # Apply delta
        content = apply_delta(base_data, delta_data)
        offset += len(data[offset:]) - len(decompressor.unused_data)
        obj_type_name = base_type

    else:
        # Regular object
        decompressor = zlib.decompressobj()
        content = decompressor.decompress(data[offset:])
        offset += len(data[offset:]) - len(decompressor.unused_data)
        obj_type_name = type_map[obj_type]

    # Store object for delta resolution
    objects_by_offset[start_offset] = (obj_type_name, content)

    sha1 = hash_object(content, obj_type_name)

    return offset, sha1

def apply_delta(base_data, delta_data):
    """Apply delta instructions to base data."""
    offset = 0

    # Read base object size
    base_size, offset = read_varint(delta_data, offset)

    # Read result object size
    result_size, offset = read_varint(delta_data, offset)

    result = bytearray()

    while offset < len(delta_data):
        instruction = delta_data[offset]
        offset += 1

        if instruction & 0x80:  # Copy instruction
            cp_offset = 0
            cp_size = 0

            # Read offset
            if instruction & 0x01:
                cp_offset = delta_data[offset]
                offset += 1
            if instruction & 0x02:
                cp_offset |= delta_data[offset] << 8
                offset += 1
            if instruction & 0x04:
                cp_offset |= delta_data[offset] << 16
                offset += 1
            if instruction & 0x08:
                cp_offset |= delta_data[offset] << 24
                offset += 1

            # Read size
            if instruction & 0x10:
                cp_size = delta_data[offset]
                offset += 1
            if instruction & 0x20:
                cp_size |= delta_data[offset] << 8
                offset += 1
            if instruction & 0x40:
                cp_size |= delta_data[offset] << 16
                offset += 1

            if cp_size == 0:
                cp_size = 0x10000

            result.extend(base_data[cp_offset : cp_offset + cp_size])
        else:  # Insert instruction
            if instruction == 0:
                raise ValueError("Invalid delta instruction")
            result.extend(delta_data[offset : offset + instruction])
            offset += instruction

    return bytes(result)

def read_size_encoding(data, offset):
    """Read size from the packfile object header."""
    byte = data[offset]
    obj_type = (byte >> 4) & 0x07
    size = byte & 0x0F
    offset += 1
    shift = 4

    while byte & 0x80:
        byte = data[offset]
        size |= (byte & 0x7F) << shift
        shift += 7
        offset += 1

    return obj_type, size, offset

def read_varint(data, offset):
    """Read Git's variable-length integer encoding (MSB format)."""
    byte = data[offset]
    value = byte & 0x7F
    offset += 1

    while byte & 0x80:
        byte = data[offset]
        value = ((value + 1) << 7) | (byte & 0x7F)
        offset += 1

    return value, offset

def checkout_tree(tree_sha, path="."):
    """Recursively checkout a tree object."""
    _, tree_content = read_object(tree_sha)

    parsed_tree = parse_tree(tree_content)
    for mode, name, entry_sha in parsed_tree:
        full_path = os.path.join(path, name.decode())
        if mode == b"40000":
            os.makedirs(full_path, exist_ok=True)
            checkout_tree(entry_sha, full_path)
        else:
            _, obj = read_object(entry_sha)
            with open(full_path, "wb") as f:
                f.write(obj)
                if mode == b"100755":
                    os.chmod(full_path, 0o755)
                else:
                    os.chmod(full_path, 0o644)



def checkout_commit(commit_sha):
    """Checkout a commit by extracting its tree."""
    _, commit_content = read_object(commit_sha)

    # Parse commit to find tree SHA
    lines = commit_content.decode().split("\n")
    tree_sha = None

    for line in lines:
        if line.startswith("tree "):
            tree_sha = line.split()[1]
            break

    if not tree_sha:
        raise ValueError("Could not find tree in commit")

    # Checkout the tree
    checkout_tree(tree_sha)



def clone_repository(repo_url, directory):
    """Clone a Git repository using Smart HTTP protocol."""
    print(f"Cloning into '{directory}'...", file=sys.stderr)

    # Create directory structure
    os.makedirs(directory, exist_ok=True)
    os.chdir(directory)
    os.makedirs(".git/objects", exist_ok=True)
    os.makedirs(".git/refs/heads", exist_ok=True)

    # Ensure URL ends properly
    if not repo_url.endswith(".git"):
        repo_url += ".git"

    # Step 1: Discover refs
    refs_url = f"{repo_url}/info/refs?service=git-upload-pack"

    req = urllib.request.Request(refs_url)
    with urllib.request.urlopen(req) as response:
        refs_data = response.read()

    lines = parse_pkt_line(refs_data)

    # Find HEAD and other refs
    head_sha = None
    refs = {}

    for line in lines:
        if line is None:
            continue

        line_str = line.decode("utf-8", errors="ignore")

        if line_str.startswith("#"):
            continue

        parts = line_str.strip().split("\x00")[0].split()
        if len(parts) >= 2:
            sha, ref = parts[0], parts[1]
            refs[ref] = sha

            if ref == "HEAD":
                head_sha = sha

    if not head_sha:
        print("Error: Could not find HEAD", file=sys.stderr)
        return

    print(f"Found HEAD at {head_sha}", file=sys.stderr)

    # Step 2: Create upload-pack request
    # Format: want <sha>\n capabilities (no capabilities for now, just want)
    capabilities = " multi_ack_detailed side-band-64k thin-pack ofs-delta"
    want_line = f"want {head_sha}{capabilities}\n"
    want_pkt = f"{len(want_line) + 4:04x}{want_line}"

    # Flush packet then done
    request_body = want_pkt.encode() + b"00000009done\n"

    print(f"Sending request: {request_body[:100]}", file=sys.stderr)

    upload_url = f"{repo_url}/git-upload-pack"

    req = urllib.request.Request(
        upload_url,
        data=request_body,
        headers={"Content-Type": "application/x-git-upload-pack-request"},
    )

    with urllib.request.urlopen(req) as response:
        pack_response = response.read()

    print(f"Received {len(pack_response)} bytes from server", file=sys.stderr)

    # The response contains side-band multiplexed data
    # We need to extract the actual packfile from band 1
    pack_data = parse_sideband_data(pack_response)

    print(f"Extracted {len(pack_data)} bytes of packfile data", file=sys.stderr)

    # Step 3: Unpack packfile
    if not pack_data.startswith(b"PACK"):
        print(
            f"Error: Invalid packfile - starts with: {pack_data[:20]}", file=sys.stderr
        )
        return

    version = struct.unpack(">I", pack_data[4:8])[0]
    num_objects = struct.unpack(">I", pack_data[8:12])[0]

    print(f"Unpacking {num_objects} objects...", file=sys.stderr)

    offset = 12
    objects_by_offset = {}

    for i in range(num_objects):
        offset, sha = unpack_object(pack_data, offset, objects_by_offset)

    # Step 4: Update HEAD and refs
    with open(".git/HEAD", "w") as f:
        f.write("ref: refs/heads/main\n")

    with open(".git/refs/heads/main", "w") as f:
        f.write(head_sha + "\n")

    # Step 5: Checkout the working tree
    checkout_commit(head_sha)

    print(f"Successfully cloned repository", file=sys.stderr)



def write_tree(directory="."):
    entries = []
    for item in sorted(os.listdir(directory)):
        if item == ".git":
            continue
        path = os.path.join(directory, item)
        if os.path.isdir(path):
            mode = b"40000"
            sha = write_tree(path)
        elif os.path.isfile(path):
            mode = b"100644"
            with open(path, "rb") as f:
                sha = hash_object(f.read())
        else:
            continue
        entries.append(mode + b" " + item.encode() + b"\x00" + bytes.fromhex(sha))
    return hash_object(b"".join(entries), "tree")

def parse_tree(content):
    rest = content
    parsed_tree = []

    while rest:
        mode, _, rest = rest.partition(b" ")
        name, _, rest = rest.partition(b"\x00")
        hashed = rest[0:20].hex()
        parsed = (mode, name, hashed)
        parsed_tree.append(parsed)
        rest = rest[20:]
    
    return parsed_tree

def commit_tree(tree_hash, message, parent=None):
    header = f"tree {tree_hash}\n"
    if parent:
        header += f"parent {parent}\n"
    return hash_object(f"{header}\n{message}\n".encode(), "commit")


def cmd_init(args):
    os.mkdir(".git")
    os.mkdir(".git/objects")
    os.mkdir(".git/refs")
    with open(".git/HEAD", "w") as f:
        f.write("ref: refs/heads/main\n")
    print("Initialized git directory")


def cmd_cat_file(args):
    _, content = read_object(args[1])
    sys.stdout.buffer.write(content)


def cmd_hash_object(args):
    with open(args[1], "rb") as f:
        data = f.read()
    print(hash_object(data))


def cmd_ls_tree(args):
    _, content = read_object(args[1])
    for _, name, _ in parse_tree(content):
        print(name.decode())


def cmd_write_tree(args):
    print(write_tree("."))


def cmd_commit_tree(args):
    tree_hash = args[0]
    parent = args[args.index("-p") + 1] if "-p" in args else None
    message = args[args.index("-m") + 1]
    print(commit_tree(tree_hash, message, parent))


def cmd_clone(args):
    clone_repository(args[0], args[1])


COMMANDS = {
    "init": cmd_init,
    "cat-file": cmd_cat_file,
    "hash-object": cmd_hash_object,
    "ls-tree": cmd_ls_tree,
    "write-tree": cmd_write_tree,
    "commit-tree": cmd_commit_tree,
    "clone": cmd_clone,
}


def main():
    command = sys.argv[1]
    if command not in COMMANDS:
        raise RuntimeError(f"Unknown command #{command}")
    COMMANDS[command](sys.argv[2:])


if __name__ == "__main__":
    main()
