"""Python wrapper for the C implementation of kuro"""

from reinkuro._clibs import kuro


def cryptbystring(input: bytes, mask: str) -> bytes:
    """Decrypts assets by applying a byte mask to the file.

    Args:
        input (bytes): The encrypted asset bytes.
        mask (str): The mask to use on the encrypted asset.

    Returns:
        bytes: Decrypted asset bytes.
    """
    return kuro.cryptbystring(input=input, mask=mask.encode("utf-16-le"), mask_len=len(mask))
