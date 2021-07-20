

## Installing
Extract the release zip and run:
```python setup.py install```

## Usage

* *As a courtesy to other fans, please refrain from spoiling unreleased story contents if any are found after decrypting.*

* **An android device with root access is required, such as an emulator**

```
Default behavior with no arguments is to attempt to decrypt the cache and export json lists of new and changed resources.

optional arguments:
  -r , --revision       The target cache revision to read during parsing for new assets. Defaults to None.
  -d, --decrypt         Decrypt and export assets after processing the database. Defaults to False.
  -e {all,new}, --export {all,new}
                        Which assets to export. Defaults to new
  -k , --key            Magic alphanumeric numbers.
  -iv , --iv            Magic base64-ish numbers.
```

Place the encrypted cache file `octocacheevai` in the root folder next to `reincli.py`.
It can be found at:

`\data\data\com.square_enix.android_googleplay.nierspjp\files\octo\pdb\201\<numbers>\octocacheevai`

The encrypted resources are located at:

`\data\data\com.square_enix.android_googleplay.nierspjp\files\v1\201\`

Move all of the files within to a folder in the script directory named `resources`. (Though only the ones with 32 character filenames such as `c2e196279db8b6a49db81e1a64cd344a` are necessary.)


## Decrypting all resources
```
python reinkuro.py --decrypt --export all
```

## Decrypting new resources
If it has been used before with an older cache version, the script may also decrypt only the new/changed resources found in the updated cache version.
(This is the default behaviour)
```
python reinkuro.py --decrypt
```
