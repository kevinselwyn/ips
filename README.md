# ips

IPS patcher

## Usage

```
IPS patcher

Usage: ./ips [options] <infile>

Option:
  -p, --patch <patchfile>  IPS patch file
  -o, --output <outfile>   Output
  -q, --quiet              Silence logging

  -h, --help               Print this help message
```

## Example

Obtain/generate IPS patch:

```
# header
printf 'PATCH' > patch.ips

# address=0x000004, length=0x0004, rle=0, data=[0x08, 0x09, 0x0a, 0x0b]
printf '\x00\x00\x04\x00\x04\x08\x09\x0a\x0b' >> patch.ips

# address=0x000000, length=0x0004, rle=1, data[0x42]
printf '\x00\x00\x00\x00\x00\x00\x04\x42' >> patch.ips

# footer
printf 'EOF' >> patch.ips
```

Obtain file to patch:

```
printf '\x00\x01\x02\x03\x04\x05\x06\x07' > input.bin
```

Build and the program:

```
make
./ips --patch patch.ips --output output.bin input.bin
```

Observe the result:

```
hexdump -C output.bin
```

Should look like:

```
00000000  42 42 42 42 08 09 0a 0b                           |B.......|
00000008
```

## Dependencies

OpenSSL is suggested, but not required. `ips` will log input and output md5
hashes. To disable this functionality, build with:

```
make OPENSSL="false"
```
