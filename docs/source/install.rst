#######
Install
#######

This guide is for installing nmeta2dpae on Ubuntu OS.

********
Pre-Work
********

Ensure packages are up-to-date
==============================

.. code-block:: text

  sudo apt-get update
  sudo apt-get upgrade

Install Python pip
==================

.. code-block:: text

  sudo apt-get install python-pip

Install git
===========

Install git and git-flow for software version control:

.. code-block:: text

  sudo apt-get install git git-flow

**********************************
Install Packages Required by nmeta
**********************************

Install coloredlogs
===================

Install coloredlogs to improve readability of terminal logs by colour-coding:

.. code-block:: text

  sudo pip install coloredlogs

Install dpkt Python Packet Library
==================================

Install dpkt for parsing packets:

.. code-block:: text

  sudo pip install dpkt

Install scapy
=============

.. code-block:: text

  sudo pip install scapy

Install pytest
==============
Pytest is used to run unit tests:

.. code-block:: text

  sudo apt-get install python-pytest

Install YAML
============

Install Python YAML ("YAML Ain't Markup Language") for parsing config
and policy files:

.. code-block:: text

  sudo apt-get install python-yaml

Install simplejson
==================

.. code-block:: text

  sudo pip install simplejson

Install mock
============

.. code-block:: text

  sudo pip install -U mock

***************
Install MongoDB
***************

MongoDB is the database used by nmeta2. Install MongoDB as per `their instructions <https://docs.mongodb.org/manual/tutorial/install-mongodb-on-ubuntu/>`_ :

Import the MongoDB public GPG Key:

.. code-block:: text

  sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv EA312927

Create a list file for MongoDB:

.. code-block:: text

  echo "deb http://repo.mongodb.org/apt/ubuntu trusty/mongodb-org/3.2 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.2.list

Reload local package database:

.. code-block:: text

  sudo apt-get update

Install MongoDB:

.. code-block:: text

  sudo apt-get install -y mongodb-org

Add pymongo for a Python API into MongoDB:

.. code-block:: text

  sudo apt-get install build-essential python-dev
  sudo pip install pymongo

Turn on smallfiles to cope with small file system size:

.. code-block:: text

  sudo vi /etc/mongod.conf

Add this to the storage section of the config:

.. code-block:: text

  mmapv1:
    smallFiles: true

Start MongoDB (if required) with:

.. code-block:: text

  sudo service mongod start

******************
Install nmeta2dpae
******************

Clone nmeta2dpae

.. code-block:: text

  cd
  git clone https://github.com/mattjhayes/nmeta2dpae.git

*******
Aliases
*******

Aliases can be used to make it easier to run common commands.
To add the aliases, edit the .bash_aliases file in your home directory:

.. code-block:: text

  cd
  sudo vi .bash_aliases

Paste in the following:

.. code-block:: text

  # Run nmeta2dpae:
  alias nm2="sudo python ~/nmeta2dpae/nmeta2dpae/nmeta2dpae.py"
  #
  # Run tests on nmeta2dpae:
  alias nm2t="cd ~/nmeta2dpae/test/; py.test"

Re-read the Aliases
===================

Read the aliases file in so that new command is available for use:

.. code-block:: text

  . ~/.bashrc

***********
Edit Config
***********

Edit the config file ~/nmeta2dpae/nmeta2dpae/config/config.yaml and update
values as appropriate. You should check:

- URL for nmeta2 under key nmeta_controller_address
- Which interfaces should sniff under key sniff_if_names
- MongoDB settings under keys mongo_addr and mongo_port

*************************
Create Custom Classifiers
*************************

Custom classifiers can be installed into the
~/nmeta2dpae/nmeta2dpae/classifiers directory. They operate per packet and are
passed a flow class object that has variables and methods that are in the
context of the current packet and the flow that it belongs to. Check out
flow.py for more information. Custom classifiers are called by declaring
them in main_policy.yaml in nmeta2 on the controller.

**************
Run nmeta2dpae
**************

.. code-block:: text

  nm2

