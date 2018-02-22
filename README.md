# psp-save

A tool for encryption or decryption of PSP saves.


## Usage

psp-save -d key mode data out (decrypt)  
psp-save -e key mode data out name sfo sfo_out (encrypt)  
mode is 1, 3 or 5  
key is the path to the 16-byte file containing the game key. the path is
ignored (but must be present) if mode is 1  
name is usually DATA.BIN for savegames
