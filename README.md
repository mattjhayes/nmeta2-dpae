# nmeta2dpae
Data Plane Auxiliary Engine (DPAE) for use with nmeta2

## Install on Ubuntu:

### Install Python YAML Library
Install YAML ("YAML Ain't Markup Language") for parsing config and policy files:
```
sudo apt-get install python-yaml
```

### Install dpkt Python Packet Library
Install dpkt for parsing packets:
```
sudo pip install dpkt
```

### Install MongoDB
Install MongoDB as per [their instructions](https://docs.mongodb.org/manual/tutorial/install-mongodb-on-ubuntu/)

### Install nmetadpae
Clone nmeta2dpae from GitHub:
```
cd
git clone git@github.com:mattjhayes/nmeta2dpae.git
```

### Set up Aliases
Set up alias in .bash_aliases. Sudo and edit the file by adding:
```
alias nm2="sudo python ~/nmeta2dpae/nmeta2dpae/nmeta2dpae.py"
```

### Edit Config
TBD
