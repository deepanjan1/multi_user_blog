# Multi User Blog

## Overview
This Multi User blog allows the following:
* A person to register as a valid user
* Write posts once registered as a user
* Edit and Delete posts created by the user
* Read and comment on all posts by all users
* Like posts not created by the user

## Installation
1. To install the blog, please download all the contents of the git repository into one directory.
2. Then, create your own config.py file with the following steps:
	* Go to your project folder and create a file called `config.py`.  You can do this on
	terminal or command line by pointing to your project folder and typing `touch config.py`
	* Open `config.py` in your favorite text editor
	* Type in the following:
	`secret = "MY_SECRET"`
	* Save and close this file.  This will create your secret phrase for hashing secure information.
2. Run a dev server locally using the command in terminal `dev_appserver.py app.yaml`
3. Then go to the server specified in your terminal and append `/blog`.  This is typically `http://localhost:8080/blog`
4. If you'd like to access the live version, please go to [Deep's Blog](https://udacity-project-deepanjan.appspot.com/blog/)