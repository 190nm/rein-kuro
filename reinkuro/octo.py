import argparse
import hashlib
import json
import re

from enum import Enum, auto
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from rich.console import Console
from rich.progress import track, Progress

from reinkuro import kuro, octodb_pb2

# Compile regex because it's used frequently
regex = re.compile(r"\)")
console = Console()

courtesy_request = "\n[bold white]>>> As a courtesy to other fans, please refrain from spoiling unreleased story contents if any are found after decrypting. <<<\n"


# Boilerplate so argparse can print readable help output if an incorrect argument is used with these enums
class ArgEnum(Enum):
    def __str__(self):
        return self.name

    def __repr__(self):
        return str(self)

    @classmethod
    def argparse(cls, string):
        try:
            return cls[string]
        except KeyError:
            raise ValueError()


class Localization(ArgEnum):
    def __new__(cls, key, iv):
        obj = object.__new__(cls)
        obj._value_ = auto()
        obj.key = bytes(key, "utf-8")
        obj.iv = bytes(iv, "utf-8")
        return obj

    # All currently known magic numbers to try
    en = ("st4q3c7p1ibgwdhm", "LvAUtf+tnz")
    jp = ("p4nohhrnijynw45m", "LvAUtf+tnz")
    encbt = ("p4nohhrnijynw45m", "LvAUtf+tnz")
    jpcbt = ("ezj749zwskuskg46", "LvAUtf+tnz")


class Decrypt(ArgEnum):
    cache_only = "cache_only"
    new = "new"
    all = "all"


def cache_from_encrypted(encrypted_cache_path: Path, key: bytes, iv: bytes) -> octodb_pb2.Database:
    """Decrypts a cache file and deserializes it to a protobuf object

    Args:
        encrypted_cache_path (Path): The path to the encrypted ``octocacheevai`` file.
        key (bytes): A byte-string. Currently 16 characters long and appears to be alpha-numeric.
        iv (bytes): A byte-string. Currently 10 characters long and appears to be base64-ish.

    Returns:
        octodb_pb2.Database: A protobuf object representing the deserialized cache.
    """

    # The actual key and iv passed in during encryption are the md5 hashes of the respective strings
    key = hashlib.md5(key).digest()
    console.print(f"key: [green]{key.hex()}[/green]")

    iv = hashlib.md5(iv).digest()
    console.print(f"iv : [green]{iv.hex()}[/green]\n")

    cipher = AES.new(key, AES.MODE_CBC, IV=iv)

    # Open the current (encrypted) octocacheevai
    try:
        data = encrypted_cache_path.read_bytes()
    except FileNotFoundError:
        console.print(
            f'[bold red]>>> [Error][/bold red] [bold]Encrypted cache "{encrypted_cache_path.name}" not found.[/bold] [bold red]<<<[/bold red]'
        )
        console.print(
            "    Place the encrypted cache file in the root folder next to the script.\n"
            '    It can be found at: "\\data\\data\\com.square_enix.android_googleplay.nierspjp\\files\\octo\\pdb\\201\\<numbers>\\octocacheevai".\n'
        )
        raise SystemExit(1)
    # For some reason there's a single extra 0x01 byte at the start of the encrypted file
    try:
        dec_bytes = unpad(padded_data=cipher.decrypt(data[1:]), block_size=16, style="pkcs7")
    except ValueError:
        # Should quit early if the supplied key is wrong somehow.
        console.print(
            f"[bold red]>>> [Error][/bold red] [bold]Key {key}is incorrect.[/bold] [bold red]<<<[/bold red]\n"
        )
        raise SystemExit(1)

    # The first 16 bytes are an md5 hash of the database that follows it, which is skipped because it's useless for this purpose
    dec_bytes = dec_bytes[16:]
    # Read the decrypted bytes to a protobuf object
    current = octodb_pb2.Database()
    current.ParseFromString(dec_bytes)
    # Revision number should probably change with every update..?
    console.print(f"Current revision : {current.revision}\n")
    # Get current localization from the folder and append it to the filename
    cache_localization = str(encrypted_cache_path.parent.name)
    current_path = encrypted_cache_path.parent.joinpath(f"decrypted/octocache_v{current.revision}.{cache_localization}")
    # Write the decrypted cache to a local file
    if not current_path.exists():
        current_path.parent.mkdir(parents=True, exist_ok=True)
        current_path.write_bytes(dec_bytes)
    return current


def dict_from_cache(cache: octodb_pb2.Database) -> dict:
    """Quick conversion to dict from a cache object. Mostly because the ``in`` operation is useful.

    Args:
        cache (octodb_pb2.Database): A protobuf object representing the deserialized cache.

    Returns:
        dict: Dictionary
    """
    return {
        "revision": cache.revision,
        "assetBundleList": {
            assetbundle.id: {
                # The "name" is actually the file path and "objectName" is the real name
                "name": assetbundle.name,
                "size": assetbundle.size,
                "crc": assetbundle.crc,
                # "deps": assetbundle.deps,
                "md5": assetbundle.md5,
                "objectName": assetbundle.objectName,
                "generation": assetbundle.generation,
            }
            for assetbundle in cache.assetBundleList
        },
        "resourceList": {
            assetbundle.id: {
                "name": assetbundle.name,
                "size": assetbundle.size,
                "crc": assetbundle.crc,
                # "deps": assetbundle.deps,
                "md5": assetbundle.md5,
                "objectName": assetbundle.objectName,
                "generation": assetbundle.generation,
            }
            for assetbundle in cache.resourceList
        },
    }


def decrypt_from_dict(asset_dict: dict, out_path: Path, localization: Enum):
    """Accepts a ``dict`` where the key is the resource ``md5`` and the value is it's ``name`` and decrypts files to the directory given in ``out_path``.
    The encrypted resource files are named after their md5 hash, and their true name is used to decrypt them.

    Args:
        asset_dict (dict): Dictionary in the format ``"md5" : "name"``
        out_path (Path): The destination folder to write decrypted files to.
    """
    contents = Path(f"resources/{localization}/").iterdir()
    # Filter for anything in the resources folder
    try:
        to_decrypt = [path for path in contents if path.name in asset_dict]
    except FileNotFoundError:
        console.print(
            f"[bold red]>>> [Error][/bold red] [bold]Folder [cyan]resources/{localization}/[/cyan] not found.[/bold] [bold red]<<<[/bold red]"
        )
        console.print(
            "    Move ALL of the encrypted resources there.\n"
            '    They can be found at: "\\data\\data\\com.square_enix.android_googleplay.nierspjp\\files\\v1\\201\\".\n'
            '    (Though only the ones with 32 character filenames such as "c2e196279db8b6a49db81e1a64cd344a" are necessary.)\n'
        )
        raise SystemExit(1)
    # Sort the list so it decrypts in order
    to_decrypt.sort(key=lambda x: asset_dict[x.name])

    if out_path.name == "all":
        # Track progress per-asset if exporting all assets
        to_decrypt = track(to_decrypt, description=f"[cyan]Decrypting {out_path.name}", console=console, transient=True)
    # for path in to_decrypt:
    for path in to_decrypt:
        buff = path.read_bytes()
        if buff[0] == 0x32:
            crypttype = "[ Version1Full ]"
        elif buff[0] == 0x31:
            crypttype = "[   Version1   ]"
        else:
            crypttype = "[     Raw      ]"

        maskstring = asset_dict[path.name]
        decrypted = kuro.cryptbystring(input=buff, mask=maskstring)
        fixedpath = re.sub(regex, "/", asset_dict[path.name])
        console.print(f"{crypttype} <{path.name}> {fixedpath}")

        file = out_path.joinpath(f"{fixedpath}.assets")
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(decrypted)


def export_all(cache: octodb_pb2.Database, localization: Enum):
    """Decrypts and exports all assets using the given cache object.

    Args:
        cache (octodb_pb2.Database): A protobuf object representing the deserialized cache.
    """
    current_dict = dict_from_cache(cache)
    all_assets = {v["md5"]: v["name"] for k, v in current_dict["assetBundleList"].items()}
    readable = {v["name"]: v["md5"] for k, v in current_dict["assetBundleList"].items()}

    export_folder = Path(f"exports/{localization}/v{cache.revision}_assets/")
    export_folder.parent.mkdir(parents=True, exist_ok=True)

    export_folder.joinpath("db.json").write_text(json.dumps(readable, sort_keys=True, indent=4))
    decrypt_from_dict(all_assets, export_folder.joinpath("all"), localization)
    # Only when decryption is performed, nicely ask user not to ruin the story for anyone, not that a line of text ever stopped anyone
    console.print(courtesy_request)


def parse_difference(
    current: octodb_pb2.Database,
    previous: octodb_pb2.Database,
    localization: Enum,
    decrypt=None,
):
    """Parses the difference between two cache objects and optionally decrypts the "new" entires in the cache, and/or exports a human-readable json of the differences.

    Args:
        current (octodb_pb2.Database): The newer cache of the two.
        previous (octodb_pb2.Database): The older cache to compare against.
        export_json ([bool], optional): Defaults to None.
        decrypt ([bool], optional): Defaults to None.
    """

    # convert to dict for access to the "in" operation
    current_dict = dict_from_cache(current)
    previous_dict = dict_from_cache(previous)

    # Compare the two for new and changed assets
    new_assets = {
        v["md5"]: v["name"]
        for k, v in current_dict["assetBundleList"].items()
        if k not in previous_dict["assetBundleList"]
    }
    changed_assets = {
        v["md5"]: v["name"]
        for k, v in current_dict["assetBundleList"].items()
        if k in previous_dict["assetBundleList"]
        and previous_dict["assetBundleList"][k]["generation"] != current_dict["assetBundleList"][k]["generation"]
    }

    export_folder = Path(f"exports/{localization}/v{current.revision}_assets/")
    export_folder.mkdir(parents=True, exist_ok=True)

    # Dump human-readable json
    export_folder.joinpath("new.json").write_text(
        json.dumps(
            {
                v["name"]: v["generation"]
                for k, v in current_dict["assetBundleList"].items()
                if k not in previous_dict["assetBundleList"]
            },
            sort_keys=True,
            indent=4,
        )
    )
    export_folder.joinpath("changed.json").write_text(
        json.dumps(
            {
                v["name"]: v["generation"]
                for k, v in current_dict["assetBundleList"].items()
                if k in previous_dict["assetBundleList"]
                and previous_dict["assetBundleList"][k]["generation"]
                != current_dict["assetBundleList"][k]["generation"]
            },
            sort_keys=True,
            indent=4,
        )
    )

    if decrypt:
        # Run the asset decrypt loop to write them to "{version}_exports/new/..." and "{version}_exports/changed/..."
        with Progress(console=console) as progress:
            task = progress.add_task("[cyan]Decrypting resources...", total=len(new_assets) + len(changed_assets))

            console.rule("[bold green]Changed")
            decrypt_from_dict(changed_assets, export_folder.joinpath("changed"), localization)
            progress.update(task, advance=len(changed_assets))

            console.rule("[bold green]New")
            decrypt_from_dict(new_assets, export_folder.joinpath("new"), localization)
            progress.update(task, advance=len(new_assets))

        console.print(f"[green]Exported decrypted asset files to:[/green] [cyan]{export_folder}[/cyan]")
        # Only when decryption is performed, nicely ask user not to ruin the story for anyone, not that a line of text ever stopped anyone
        console.print(courtesy_request)


def init_arguments(args=None) -> argparse.Namespace:
    """Initialize command line arguments.

    Args:
        args ([str], optional): Arguments passed in as a string for testing purposes. Defaults to None.
    Returns:
        argparse.Namespace: [description]
    """
    parser = argparse.ArgumentParser(
        # usage="%(prog)s [OPTION]...",
        description="\nFirst time setup:\n\n"
        " ●  An android device with root access (such as an emulator) is required to use this tool.\n"
        ' ●  Create a new folder at "/caches/<platform>/" in the current working directory where <platform> is the localization to decrypt.\n'
        '       (i.e for the japanese release: "/caches/jp/".)\n'
        ' ●  Move the encrypted cache file "octocacheevai" to the new folder. It can be found at:\n'
        '       "\\data\\data\\com.square_enix.android_googleplay.nierspjp\\files\\octo\\pdb\\201\\<numbers>\\octocacheevai".\n'
        ' ●  Create another new folder at "/resources/<platform>/" using the same localization as before for <platform>.\n'
        " ●  Move ALL of the encrypted resources there. They can be found at:\n"
        '       "\\data\\data\\com.square_enix.android_googleplay.nierspjp\\files\\v1\\201\\".\n'
        '       (In particular, only the ones with 32 character filenames such as "c2e196279db8b6a49db81e1a64cd344a" are necessary.)\n'
        "\nUsage:\n"
        "\nThe tool is now ready to be used.\n"
        " ●  Example: Decrypting all english resources\n"
        '\n    "reinkuro --localization english --decrypt all"\n'
        " ●  When run with no arguments, the default behavior is to decrypt the japanese cache and export the differences to json.\n",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-d",
        "--decrypt",
        type=Decrypt.argparse,
        choices=list(Decrypt),
        default=Decrypt.cache_only,
        help="Which assets to decrypt. Defaults to cache_only, which will only export differences to json.",
    )
    parser.add_argument(
        "-l",
        "--localization",
        type=Localization.argparse,
        choices=list(Localization),
        default=Localization.jp,
        help="Which localization to target. Defaults to jp. Also supports cache files from the closed beta releases.",
    )
    parser.add_argument(
        "-r",
        "--revision",
        type=int,
        default=None,
        metavar="",
        help="The target cache revision to read during parsing for new assets. Defaults to None.",
    )
    # These are just "magic numbers" pay no attention to them
    parser.add_argument(
        "-k",
        "--key",
        type=str,
        default=None,
        metavar="",
        help="Manually specifcy a new key. Hint: Magic alphanumeric numbers.",
    )
    parser.add_argument(
        "-iv",
        "--iv",
        type=str,
        default=None,
        metavar="",
        help="Manually specify a new iv. Hint: Magic base64-ish numbers.",
    )
    return parser.parse_args(args=args)


def cli(__args__):
    # If the key and/or iv are specified via argument, they are converted to bytes for hashing
    key = bytes(__args__.key, "utf-8") if __args__.key else __args__.localization.key
    iv = bytes(__args__.iv, "utf-8") if __args__.iv else __args__.localization.iv
    console.print(f"\n{__args__}\n")
    # Create current database object i.e caches/jp/octocacheevai
    cache_path = Path(f"caches/{__args__.localization}/")
    current = cache_from_encrypted(cache_path.joinpath("octocacheevai"), key=key, iv=iv)
    if __args__.revision:
        previous_revision = __args__.revision
    else:
        cache_revisions = [int(file.stem[11:]) for file in cache_path.joinpath("decrypted/").iterdir()]
        cache_revisions.remove(current.revision)
        previous_revision = max(cache_revisions) if cache_revisions else None
    console.print(f"Previous revision: {previous_revision}\n")
    # Create previous database object
    previous = octodb_pb2.Database()
    try:
        # i.e caches/jp/octocache_v133.jp
        previous.ParseFromString(
            cache_path.joinpath(f"decrypted/octocache_v{previous_revision}.{__args__.localization}").read_bytes()
        )
    except FileNotFoundError:
        console.print(
            f"[bold red]>>> [Warning][/bold red] [bold]Cache revision {previous_revision} not found.[/bold] [bold red]<<<[/bold red]"
        )

    if __args__.decrypt == Decrypt.cache_only:
        parse_difference(current, previous, localization=__args__.localization, decrypt=False)
    elif __args__.decrypt == Decrypt.new:
        parse_difference(current, previous, localization=__args__.localization, decrypt=True)
    elif __args__.decrypt == Decrypt.all:
        export_all(current)
    else:  # Should be unreachable
        pass


def main():
    __args__ = init_arguments()
    cli(__args__)


if __name__ == "__main__":
    main()
