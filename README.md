# Python Flask and Okta cloud (Identity & Access Management)

This is a file hasing app that gives users the option to login so they may keep track of their previously requested hash values. 
We’ll use a free account on Okta to register our web app so we can create, manage and maintain the users for the app

## Setting up an Okta app to connect to your Python Flask app
- Create an Okta account on developer.okta.com
- Create OpenID Connect App
- create an Authorization Token
- Enable User Registration (optional)


                                                           Okta IAM Cloud    
            |Flask App|          ----------->         (users / permissions)
       (File Hashing Function)                      
               
                    ^ 
                    | 
                    |           
                    |           
         
         User Web Browser
          URL: http://localhost:5000
            
                               











