def split(buf: bytes, lim: int) -> list[bytes]:
    """
    Split a byte buffer into chunks of specified size.
    
    Args:
        buf: The byte buffer to split
        lim: The maximum size of each chunk
        
    Returns:
        A list of byte chunks
    """
    chunks = []
    
    while len(buf) >= lim:
        chunk, buf = buf[:lim], buf[lim:]
        chunks.append(chunk)
    
    if len(buf) > 0:
        chunks.append(buf)
    
    return chunks


def splits(s: str, n: int) -> list[str]:
    """
    Split a string into chunks of n characters (counting by runes/characters).
    
    Args:
        s: The string to split
        n: The number of characters per chunk
        
    Returns:
        A list of string chunks
    """
    sub = ""
    subs = []
    
    # Python strings already handle Unicode properly
    for i, char in enumerate(s):
        sub += char
        if (i + 1) % n == 0:
            subs.append(sub)
            sub = ""
        elif (i + 1) == len(s):
            subs.append(sub)
    
    return subs
