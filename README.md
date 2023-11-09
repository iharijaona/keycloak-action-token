Keycloak Action Token
=====================
Use action token to integrate an external application in the Authentication Flow 

Invoke external application within the authentication
flow :

1. During authentication, a custom authenticator that mandates cooperation with
   external application is invoked.

2. This authenticator prepares an action token for the current authentication
   session and redirects to the application, passing the action token along.

3. The application does whatever it is suited for, e.g. perform authentication
   of the user with some custom advanced credential type (facial authentication).

4. Application uses the action token obtained in Step 2. to return back to
   authentication flow, providing the authenticator with its own signed token
   containing values entered by the user.

5. The handler handling that action token takes values of the fields and sets
   the attributes of authenticating user accordingly.


Build and Deploy the Quickstart
-------------------------------

```
docker run -it --rm --name build-keycloak-action-token -v "$(pwd)/.m2":/root/.m2 -v "$(pwd)":/usr/src/keycloak-2fa-sms -w /usr/src/keycloak-action-token maven:3.8-jdk-11 mvn clean package

```