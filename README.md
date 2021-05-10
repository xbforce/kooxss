# KooXSS
KooXSS checks responses for some special characters like ```< " ' >``` to see if they are not sanitized. It simply speeds up the process of finding XSS, so after recognizing suspicious URLs and parameters you can do more test to check if you can get any XSS.

Koo means where; KooXSS means where is XSS! Pronounce it like: ```Koo XSS``` or ```kooks ss```.

**Requirements**

To run this tool you need to install ```urldedupe``` and ```sponge``` first.

```urldedupe``` makes URLs unique based on their parameters.

```sponge``` saves the output directly to the file it read. For example instead of using:

```
sort -u myfile.txt > tmp_myfile.txt
mv tmp_myfile.txt myfile.txt
```

We can do this:

```
sort -u myfile.txt | sponge myfile.txt
```

Download and install urldedupe from **Ameen Maali**'s github:

```
https://github.com/ameenmaali/urldedupe
```

Don't forget to copy the tool in ```/usr/local/bin```:

```
sudo cp urldedupe /usr/local/bin
```

Download and install sponge from **Joey Hess** website:

```
https://joeyh.name/code/moreutils/
```

Or simply follow these steps to install sponge:

```
git clone git://git.joeyh.name/moreutils
cd moreutils/
gcc sponge.c -o sponge
sudo cp sponge /usr/local/bin/
```

**Install KooXSS:**

```
git clone https://github.com/xbforce/kooxss.git
cd kooxss
chmod +x kooxss.sh
sudo cp kooxss.sh /usr/local/bin/kooxss
```

Now you can run **KooXSS** from any directory.

</br>

**USAGE**

You only need to put URLs in a file and use that file as an argument in kooxss:

```
$ kooxss urls.txt
```

KooXSS will get rid of URLs which don't have any parameter. It also makes the list of URLs unique to avoid testing a URL twice.
URLs should start with ```http``` or ```https```.

Hope it helps you find some XSS;)
