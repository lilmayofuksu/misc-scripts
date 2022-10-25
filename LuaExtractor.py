import enum
import os, sys
import re
from typing import List

r = re.compile(rb'\x1bLuaS\x00', re.DOTALL)

def main(lua_path: str) -> None:
    f = open(lua_path, 'rb+')
    data = f.read()

    matches = [i for i in r.finditer(data)]

    asd = lambda matches, x: [matches[i:i+x] for i in range(0, len(matches), 2)]
    #final_list: List[List[re.Match[bytes]]] = asd(matches, 2)
    print(len(matches))


    for idx, i in enumerate(matches):
        beg_offset = i.start()
        if idx == len(matches) - 1:
            f.seek(0, os.SEEK_END)
            end_offset = f.tell()
        else:
            end_offset = matches[idx+1].start()

        """
        chunk_1 = i[0].group()
        beg_offset = i[0].start()
        if len(i) > 1:
            chunk_2 = i[1].group()
            end_offset = i[1].start() - 1
        else:
            f.seek(0, os.SEEK_END)
            end_offset = f.tell()
        """

        f.seek(beg_offset)
        luachunk = f.read(end_offset - beg_offset)
    
        #Make a folder
        if not os.path.exists(f'luas/{lua_path.replace(".bytes", "")}_chunks'):
            os.makedirs(f'luas/{lua_path.replace(".bytes", "")}_chunks')

        with open(f'luas/{lua_path.replace(".bytes", "")}_chunks/{idx}.luac', 'wb') as luafile:
            luafile.write(luachunk)
            print(f'{idx}.luac saved!')

        #print(f'{idx} - LuaS at {i.start()}')
        #print(i.group())
        #print('\n')
        #print(chunk_1, chunk_2)


if __name__ == '__main__':

    if len(sys.argv) != 2:
        print('HSR Lua Extractor')
        print('Usage: {} <lua bytes>'.format(sys.argv[0]))
        sys.exit(1)

    lua = sys.argv[1]
    if os.path.isfile(lua):
        main(lua)
    else:
        print(f'Cannot find {lua}, please check your path.')
        sys.exit(1)
