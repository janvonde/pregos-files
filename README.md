# pregos files

### About

This project let you share files for a limited time. I used to use [Filez] but it stopped to work for me so I decided
to replace it with an own PHP script.



### Features
  * Upload files that expire after a time period
  * Random download name that can't be guessed easily
  * Optional a custom download name may be choosen
  * Optional a download can be secured with a password
  * Email notification when a file is downloaded
  * Email notification before a file expired
  * User authentication for file upload
  * Default and Admin user roles
  * Admin users may add new users and see a list of all files available



### Installation
You need an Apache webserver with mod_rewrite, php, php5-sqlite extensions enabled.  Clone the repository and put all files in the root folder of a vhost. Make sure, that the
.htaccess file is recognized with AllowOverride All.
Afterwards adjust the three settings in inc/config.inc.php. Start your webbrowser and open the index.php file. A database file is created automatically, username and password 
will be shown.

For deletion of expired files setup a daily cronjob that calls index.php?fileMaintenance=true, for instance like this:

```
#
# Delete expired and send email notification about soon expiring files
#

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root

23 4   * * *  www-data    curl -o /dev/null --silent http://files.example.com/index.php?fileMaintenance=true

```



### Changelog
- 2016-01-31: initial public release



### Credits
- Authentication: [Simple HTTP authentication example]
- Favicon: [Hand drawn, links, share, social icon]
- PHP function: [PHP: How to Get the Current Page URL]

### License
[Apache Licence 2.0]



[Apache Licence 2.0]:http://www.apache.org/licenses/LICENSE-2.0
[Filez]:https://github.com/FileZ/FileZ
[Simple HTTP authentication example]:https://www.jonasjohn.de/snippets/php/auth.htm
[Hand drawn, links, share, social icon]:https://www.iconfinder.com/icons/492962/hand_drawn_links_share_social_icon
[PHP: How to Get the Current Page URL]:http://webcheatsheet.com/php/get_current_page_url.php
