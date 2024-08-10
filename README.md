[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/vB1apsQV)
# 50.005 Programming Assignment 2

This assignment requires knowledge from Network Security and basic knowledge in Python.

## Secure FTP != HTTPs

Note that you will be implementing Secure FTP as your own whole new application layer protocol. In NO WAY we are relying on HTTP/s. Please do not confuse the materials, you don't need to know materials in Week 11 and 12 before getting started.

## Running the code

### Install required modules

This assignment requires Python >3.10 to run.

You can use `pipenv` to create a new virtual environment and install your modules there. If you don't have it, simply install using pip, (assuming your python is aliased as python3):

```
python3 -m pip install pipenv
```

Then start the virtual environment, upgrade pip, and install the required modules:

```
pipenv shell
python -m ensurepip --upgrade
pip install -r requirements.txt
```

If `ensurepip` is not available, you need to install it, e.g with Ubuntu:

```
# Adjust for your python version
sudo apt-get install python3.10-venv
```

### Run `./cleanup.sh`

Run this in the root project directory:

```
chmod +x ./cleanup.sh
./cleanup.sh
```

This will create 3 directories: `/recv_files`, `/recv_files_enc`, and `/send_files_enc` in project's root. They are all empty directories that can't be added in `.git`.

### Run server and client files

In two separate shell sessions, run (assuming you're in root project directory):

```
python3 source/ServerWithoutSecurity.py
```

and:

```
python3 source/ClientWithoutSecurity.py
```
Note that we have implemented ClientWithSecurity[AP|CP1|CP2].py files as well as the respective ServerWithSecurity[AP|CP1|CP2].py files.

### Using different machines

You can also host the Server file in another computer:

```sh
python3 source/ServerWithoutSecurity.py [PORT] 0.0.0.0
```

The client computer can connect to it using the command:

```sh
python3 source/ClientWithoutSecurity.py [PORT] [SERVER-IP-ADDRESS]
```

### Exiting pipenv shell

To exit pipenv shell, simply type:

```
exit
```

Do not forget to spawn the shell again if you'd like to restart the assignment.

### Uploading files from client side

To upload files, key in the path to the desired file that you would like to upload. For example, if you want to upload file.txt, (assuming you are in the root project directory):

```
files/file.txt
```

### Sustainability feature
We have implemented file compression measures before encryption and uploading of the files to optimise file transfer. This allows us to transfer files efficiently, minimising energy and network usage, which can be helpful, especially for large files. 

### Inclusivity feature
The code provides informative and user-friendly error statements that help all users easily identify the source of failure and also provide the possible actionable steps they can take to resolve such issues. 
