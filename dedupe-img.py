from PIL import Image
from pillow_heif import register_heif_opener
import click
import pickle
import hashlib
import sys
import os

EXTENSIONS = {".jpg", ".jpeg", ".heic"}
EXCLUDE_DIRECTORIES = {"@eaDir"}
HASHES_FILENAME = "dedup-hashes.pkl"

@click.group()
def cli():
    pass

@cli.command()
@click.argument('paths', nargs=-1)
def scan(paths):
    """
    Recursively scans files and subdirectories within given paths.
    """

    if len(paths) == 0:
        click.echo("usage: python dedup-img.py scan paths...")
        sys.exit(1)

    click.echo(f"scanning {paths}")

    # First pass, generate filename => hash dict
    hashes = read_dict()

    try:
        for path in paths:
            if not os.path.exists(path):
                print(f"Error: Path '{path}' does not exist.")
                continue
            if not os.path.isdir(path):
                print(f"Error: Path '{path}' is not a directory.")
                continue
            for root, dirs, files in os.walk(path):
                # Modify the 'dirs' list in-place to exclude unwanted directories
                # This ensures os.walk will not recurse into these directories
                dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRECTORIES]

                for file_name in files:
                    _, ext = os.path.splitext(file_name)
                    if ext.lower() in EXTENSIONS:
                        file_path = os.path.join(root, file_name)
                        if file_path not in hashes:
                            try:
                                h = hash_image(file_path)
                            except OSError as e:
                                print(f"error hashing '{file_path}: {e}")
                                continue
                            hashes[file_path] = h
                            print(f"hash for '{file_path}': {h}")
    except KeyboardInterrupt:
        print("Script interrupted. Saving state to disk...")
        write_dict(hashes)
        sys.exit(0)

    write_dict(hashes)
    
    # Second pass, filter hashes to only those that begin with one of the paths we're scanning
    # We could have loaded hashes from disk that are not for directories we're scanning
    hashes = {file_path: h for file_path, h in hashes.items() if startswith(file_path, paths)}
    num = len(hashes)
    print(f"Filtered to {num} hashes")

    # Third pass, generate hash => filenames dict
    reverse_hashes = dict()
    
    for file_path, h in hashes.items():
        if h in reverse_hashes:
            reverse_hashes[h].append(file_path)
        else:
            reverse_hashes[h] = [file_path]

    # Fourth pass, print duplicates
    for h, duplicates in reverse_hashes.items():
        if len(duplicates) < 2:
            continue
        print(f"Duplicate {h}")
        for duplicate in duplicates:
            print(duplicate)

def startswith(file_path, paths):
    for path in paths:
        if file_path.startswith(path):
            return True
    return False

def write_dict(hashes):
    with open(HASHES_FILENAME, 'wb') as file_handler:
        pickle.dump(hashes, file_handler)
        num = len(hashes)
        print(f"Wrote {num} hashes to disk")

def read_dict():
    if not os.path.exists(HASHES_FILENAME):
        print("No hashes loaded from disk, starting from scratch...")
        return dict()

    try:
        with open(HASHES_FILENAME, 'rb') as file_handler:
            hashes = pickle.load(file_handler)
            num = len(hashes)
            print(f"Loaded {num} hashes from disk")
            return hashes
    except Exception as e:
        print(f"Error {e} loading hashes from disk, starting from scratch...")
        return dict()

def hash_image(image_path):
    """
    Computes the MD5 hash of an image's pixel data, ignoring EXIF metadata.

    Args:
        image_path (str): The path to the image file.

    Returns:
        str: The hexadecimal representation of the MD5 hash.
    """
    with Image.open(image_path) as img:
        pixel_data = img.tobytes()
        
        image_hash = hashlib.md5(pixel_data).hexdigest()
        return image_hash

@cli.command()
def cleanup():
    """
    Clean up computed hashes for deleted files.
    """
    hashes = read_dict()
    for file_path, h in hashes.items():
        if not os.path.exists(file_path):
            print(f"file {file_path} no longer exists")
            del hashes[h]
    
    write_dict(hashes)

if __name__ == "__main__":
    register_heif_opener()
    cli()
