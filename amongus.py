import os, sys, re

if __name__ == "__main__":
    # Path to the binary from argv
    binary = sys.argv[1]

    # Open the binary
    with open(binary, "rb") as f:
        pattern = rb"\x62\x06\x70\x72\x6F\x74\x6F\x33\x00"
        data = f.read()
        match: list[re.Match] = list(re.finditer(pattern, data))

        if match:
            for idx, m in enumerate(match):
                endoffset = m.start()
                startoffset = endoffset
                # Travel backwards until we find 0x000A
                while True:
                    if data[startoffset] == 0x00 and data[startoffset + 1] == 0x0A:
                        break
                    startoffset -= 1
                
                if data[startoffset] == 0x00 and data[startoffset + 1] == 0x0a:
                    binary_data = data[startoffset+1:endoffset]

                    with open(f"out/{idx}.bin", "wb") as outf:
                        outf.write(binary_data)

