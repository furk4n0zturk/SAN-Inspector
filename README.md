# SAN-Inspector

SAN-Inspector is a Python tool used to check the SAN (Subject Alternative Name) values in SSL certificates of given domain names.

## Installation

1. Clone or download this GitHub repository.

```
git clone https://github.com/furk4n0zturk/SAN-Inspector.git
```

2. Navigate to the downloaded folder.

```
cd SAN-Inspector
```

3. Install the requirements.

```
pip3 install -r requirements.txt
```

## Usage

You can use the SAN-Inspector tool with a single `host:port` pair or a file containing `host:port` pairs.

### For a single URL

```
python3 saninspector.py -u example.com:443
```

### For a file containing a list of URLs

```
python3 saninspector.py -uL hostlist.txt
```
