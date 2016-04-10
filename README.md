# nmeta2dpae
Data Plane Auxiliary Engine (DPAE) for use with nmeta2

## Install on Ubuntu:

### Ensure packages are up-to-date
```
sudo apt-get update
sudo apt-get upgrade
```

### Install Python pip
```
sudo apt-get install python-pip
```

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

Add pymongo for a Python API into MongoDB:
```
sudo pip install pymongo
```

Create a directory for the database:
```
sudo mkdir -p /data/db
```

Turn on smallfiles to cope with small file system size:
```
sudo vi /etc/mongod.conf
```

Add this to the storage section of the config:
```
  mmapv1:
    smallFiles: true
```

Start MongoDB with:
```
sudo service mongod start
```

### Install scapy
```
sudo pip install scapy
```

### Install nmetadpae
Clone nmeta2dpae from GitHub:
```
cd
git clone https://github.com/mattjhayes/nmeta2dpae.git
```

### Set up Aliases
Set up alias in .bash_aliases. Sudo and edit the file by adding:
```
alias nm2="sudo python ~/nmeta2dpae/nmeta2dpae/nmeta2dpae.py"
```

### Edit Config
Edit the config file `~/nmeta2dpae/nmeta2dpae/config/config.yaml` and update values as appropriate. You should check:
* URL for nmeta2 under key `nmeta_controller_address`
* Which interfaces should sniff under key `sniff_if_names`
* MongoDB settings under keys `mongo_addr` and `mongo_port`

## Create Custom Classifiers
Custom classifiers can be installed into the `~/nmeta2dpae/nmeta2dpae/classifiers` directory.
They operate per packet and are passed a flow class object that has variables and methods that are in the context of the current packet and the flow that it belongs to. Check out flow.py for more information.
Custom classifiers are called by declaring them in main_policy.yaml in nmeta2 on the controller.

## Test
```
nm2t
```

## Run
```
nm2
```
