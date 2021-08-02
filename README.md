

## Installing
Extract the release zip, then compile it:

```
python setup.py build_ext --inplace
```

On windows you may need to install the [Python native development tools](https://docs.microsoft.com/en-us/visualstudio/python/installing-python-support-in-visual-studio?view=vs-2019#:~:text=Installs%20the%20C%2B%2B%20compiler%20and%20other%20necessary%20components) from visual studio first.

Then, install the package:

```
python setup.py install
```
## For those who c[A]re:

* *As a courtesy to other fans, please refrain from spoiling unreleased **story contents** if any are found after decrypting.*


## First time setup

* **An android device with root access (such as an emulator) is required to use this tool.**

*  Create a new folder at **`/caches/<platform>/`** in the ***current working directory*** where **`<platform>`** is the localization to decrypt.

*(i.e for the japanese release: **`/caches/jp/`**.)*

* Move the encrypted cache file **`octocacheevai`** to the new folder. It can be found at:

**`\data\data\com.square_enix.android_googleplay.nierspjp\files\octo\pdb\201\<numbers>\octocacheevai`**

* Create another new folder at **`/resources/<platform>/`** using the same localization as before for **`<platform>`**.

Move *ALL* of the encrypted resources there. They can be found at:

`\data\data\com.square_enix.android_googleplay.nierspjp\files\v1\201\`.

*(In particular, only the ones with 32 character filenames such as `c2e196279db8b6a49db81e1a64cd344a` are necessary.)*

The tool is now ready to be used.

## Usage



* Example: Decrypting all english resources
```
reinkuro --localization english --decrypt all
```

* When run with no arguments, the default behavior is to decrypt the japanese cache and export the differences to json.
```
optional arguments:
  -h, --help            show this help message and exit
  -d {cache_only,new,all}, --decrypt {cache_only,new,all}
                        Which assets to decrypt. Defaults to cache_only, which will only export differences to json.
  -l {en,jp,encbt,jpcbt}, --localization {en,jp,encbt,jpcbt}
                        Which localization to target. Defaults to jp. Also supports cache files from the closed beta releases.
  -r , --revision       The target cache revision to read during parsing for new assets. Defaults to None.
  -k , --key            Manually specifcy a new key. Hint: Magic alphanumeric numbers.
  -iv , --iv            Manually specify a new iv. Hint: Magic base64-ish numbers.
```
