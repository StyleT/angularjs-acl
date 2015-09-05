# Angular ACL

---

## About
Angular ACL _(Access Control List)_ is a service that allows you to protect/show content based on the current user's assigned role(s),
and those role(s) permissions (abilities).

For the purposes of this documentation:
- a **resource** is an object to which access is controlled.
- a **role** is an object that may request access to a Resource.

Put simply, **roles request access to resources**. For example, if a parking attendant requests access to a car,
then the parking attendant is the requesting role, and the car is the resource, since access to the car may not be granted to everyone.

Through the specification and use of an ACL, an application may control how roles are granted access to resources.

## How secure is this?

A great analogy to ACL's in JavaScript would be form validation in JavaScript.  Just like form validation, ACL's in the
browser can be tampered with. However, just like form validation, ACL's are really useful and provide a better experience
for the user and the developer. Just remember, **any sensitive data or actions should require a server (or similar) as the final authority**.

#### Example Tampering Scenario

The current user has a role of "guest".  A guest is not able to "create_users".  However, this sneaky guest is clever
enough to tamper with the system and give themselves that privilege. So, now that guest is at the "Create Users" page,
and submits the form. The form data is sent the the server and the user is greeted with an "Access Denied: Unauthorized"
message, because the server also checked to make sure that the user had the correct permissions.

Any sensitive data or actions should integrate a server check.