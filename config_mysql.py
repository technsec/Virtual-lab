# /*****************************************************************************
# * Copyright (c) 2016, Palo Alto Networks. All rights reserved.              *
# *                                                                           *
# * This Software is the property of Palo Alto Networks. The Software and all *
# * accompanying documentation are copyrighted.                               *
# *****************************************************************************/
#
# Copyright 2016 Palo Alto Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import subprocess
import os
import logging
import urllib2
import time
import shlex

LOG_FILENAME = 'azure.log'
logging.basicConfig(filename=LOG_FILENAME,level=logging.INFO, filemode='w')
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def main():
    if (config_mysql() == 'false'):
        logger.info("[ERROR]: Config mysql error")
        return

def config_mysql():
    logger.info("[INFO]: Install and Config mysql-server")
    publicip = ""
    while (True):
        #Can I reach outside??
        try:
            publicip = urllib2.urlopen('http://ip.42.pl/raw').read()
        except Exception as e:
            logger.info("[ERROR]: Getting public IP address : {}".format(e))
            return  'false'
        else:
            logger.info("[INFO]: Should have public IP address %s " % (publicip))

        if (publicip == ""):
            time.sleep(15) #Wait annd try again
            continue
        else:
        #This means we were able to reach the outside world. Which means the firewall was configured properly.
        #Now there is a possibility that we got the packets out when firewall has just the dummy allow all outbound rule (before it is truly configured)
            break

    try:
        subprocess.check_output(shlex.split("sudo apt-get update"))
    except subprocess.CalledProcessError, e:
        looger.info("[ERROR]: apt-get update error")
        return 'false'

    try:
        subprocess.check_output(shlex.split("sudo apt-get -y install debconf-utils"))
    except subprocess.CalledProcessError, e:
        logger.info("[ERROR]: apt-get install debconf-utils error")
        return 'false'

    #Set root password to paloalto@123 before we install mysql so we can doa non-interactive setup
    try:
        #subprocess.check_output(shlex.split("sudo debconf-set-selections <<< \"mysql-server mysql-server/root_password password paloalto@123\""))
        subprocess.check_output(shlex.split("echo \"mysql-server mysql-server/root_password password paloalto@123\" | sudo debconf-set-selections"))
    except subprocess.CalledProcessError, e:
        looger.info("[ERROR]: set root password error")
        return 'false'

    try:
        #subprocess.check_output(shlex.split("sudo debconf-set-selections <<< \"mysql-server mysql-server/root_password_again password paloalto@123\""))
        subprocess.check_output(shlex.split("echo \"mysql-server mysql-server/root_password_again password paloalto@123\" | sudo debconf-set-selections"))
    except subprocess.CalledProcessError, e:
        looger.info("[ERROR]: set root password again error")
        return 'false'


    try:
        subprocess.check_output(shlex.split("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-server"))
    except subprocess.CalledProcessError, e:
        looger.info("[ERROR]: apt-get install mysql-server error")
        return 'false'

    #No need to do this as Ubuntu 16.04 has MySQL v 5.7.6 and the db is already initialized
    #try:
    #    subprocess.check_output(shlex.split("sudo mysql_install_db"))
    #except subprocess.CalledProcessError, e:
    #    looger.info("[ERROR]: mysql_install_db error")
    #    return 'false'

    #mysql_secure_installation is interactive so we need to do it's steps manually!
    #try:
    #    subprocess.check_output(shlex.split("sudo mysql_secure_installation"))
    #except subprocess.CalledProcessError, e:
    #    looger.info("[ERROR]: mysql_secure_installation error")
    #    return 'false'

    # Make sure that NOBODY can access the server without a password
    try:
        subprocess.check_output(shlex.split("mysql -uroot -ppaloalto@123 -e \"DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');\""))
    except subprocess.CalledProcessError, e:
        looger.info("[ERROR]: Access via password error")
        return 'false'

    # Delete the anonymous users
    try:
        subprocess.check_output(shlex.split("mysql -uroot -ppaloalto@123 -e \"DELETE FROM mysql.user WHERE User='';\""))
    except subprocess.CalledProcessError, e:
        looger.info("[ERROR]: Delete anon users error")
        return 'false'


    try:
        subprocess.check_output(shlex.split("mysql -uroot -ppaloalto@123 -e \"DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';\""))
    except subprocess.CalledProcessError, e:
        looger.info("[ERROR]: Delete anon users error")
        return 'false'


    try:
        subprocess.check_output(shlex.split("mysql -uroot -ppaloalto@123 -e \"FLUSH PRIVILEGES;\""))
    except subprocess.CalledProcessError, e:
        looger.info("[ERROR]: Flush privileges error 1")
        return 'false'


    #In Ubuntu 16.04 (and mysql-server5.7 mysql conf file location has changed)
    try:
        subprocess.check_output(shlex.split('sudo sed -i "s/.*bind-address.*/bind-address = 0.0.0.0/" /etc/mysql/mysql.conf.d/mysqld.cnf'))
    except subprocess.CalledProcessError, e:
        looger.info("[ERROR]: set bind address error")
        return 'false'


    #Restart mysql service
    try:
        subprocess.check_output(shlex.split("sudo systemctl restart mysql"))
    except subprocess.CalledProcessError, e:
        looger.info("[ERROR]: mysql restart error")
        return 'false'

    logger.info("[INFO]: Setting up a new user for demo username=demouser, password=paloalto@123")


    try:
        subprocess.check_output(shlex.split("mysql -uroot -ppaloalto@123 -e \"CREATE DATABASE Demo;\""))
    except subprocess.CalledProcessError, e:
        looger.info("[ERROR]: Create database error")
        return 'false'


    try:
        subprocess.check_output(shlex.split("mysql -uroot -ppaloalto@123 -e \"CREATE USER 'demouser'@'%' IDENTIFIED BY 'paloalto@123';\""))
    except subprocess.CalledProcessError, e:
        looger.info("[ERROR]: Create user error")
        return 'false'


    try:
        subprocess.check_output(shlex.split("mysql -uroot -ppaloalto@123 -e \"GRANT ALL PRIVILEGES ON Demo.* TO 'demouser'@'%';\""))
    except subprocess.CalledProcessError, e:
        looger.info("[ERROR]: Grant privileges to demouser error")
        return 'false'


    try:
        subprocess.check_output(shlex.split("mysql -uroot -ppaloalto@123 -e \"FLUSH PRIVILEGES;\""))
    except subprocess.CalledProcessError, e:
        looger.info("[ERROR]: Flush privileges error 2")
        return 'false'


    logger.info("[INFO]: MYSQL setup complete")
    return 'true'



if __name__ == "__main__":
    main()

