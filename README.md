# Angular ACL

[![Build Status](https://travis-ci.org/StyleT/angularjs-acl.svg?branch=master)](https://travis-ci.org/StyleT/angularjs-acl)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](https://github.com/StyleT/angularjs-acl/blob/master/LICENSE)

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

## Quick Examples
First you need to install this library :) It's available via bower or npm:
- `npm install --save angularjs-acl`
- `bower install --save angularjs-acl`
and add a `<script>` to your `index.html`:
```html
<!-- For bower -->
<script src="/bower_components/angularjs-acl/dist/acl.js"></script>

<!-- For npm -->
<script src="/node_modules/angularjs-acl/dist/acl.js"></script>
```

#### Set Data
Add `ng-acl` to your app module's dependencies & setup the `AclService` in `run()` block.
```js
angular.module('myApp', ['ng-acl']);

app.run(['AclService', function (AclService) {
    //All these actions you also can do in the middle of app execution
    AclService.addRole('guest');
    AclService.addRole('user', 'guest');
    AclService.addRole('admin', 'user');

    AclService.addResource('Post');
    AclService.addResource('Users');
    AclService.addResource('AdminPanel');

    AclService.allow('guest', 'Post', 'view');

    //Users can edit edit their own posts & view it because user inherits all guest permissions
    AclService.allow('user', 'Post', 'edit', function (role, resource, privilege) {
        return resource.authorId === role.id;
    });

    //Full access to all actions that available for Post
    AclService.allow('admin', 'Post');
    AclService.allow('admin', 'AdminPanel');

    //Let's assume that you have some user object that implements AclRoleInterface. This is optional feature.
    var user = {
        id: 1,
        name: 'Duck',
        getRoles: function () {
            return ['user'];
        },
    };
    AclService.setUserIdentity(user);
}]);
```

#### Protect a route

If the current user tries to go to the `/admin_panel` route, they will be redirected because the current user is a `user`, and `AdminPanel` is not one of a member role's abilities.

However, when the user goes to `/posts/2`, route will work as normal, since the user has permission.

```js
app.config(['$routeProvider', function ($routeProvider) {
  $routeProvider
    .when('/admin_panel', {
      resolve : {
        'acl' : ['$q', 'AclService', function($q, AclService){
          if(AclService.can('AdminPanel')){
            // Has proper permissions
            return true;
          } else {
            // Does not have permission
            return $q.reject('Unauthorized');
          }
        }]
      }
    });
    .when('/posts/:id', {
      resolve : {
        'acl' : ['$q', 'AclService', function($q, AclService){
          if (AclService.can('Post', 'view')) {
            return true;
          } else {
            return $q.reject('Unauthorized');
          }
        }]
      }
    });
}]);

app.run(['$rootScope', '$location', function ($rootScope, $location) {
  // If the route change failed due to our "Unauthorized" error, redirect them
  $rootScope.$on('$routeChangeError', function(current, previous, rejection){
    if(rejection === 'Unauthorized'){
      $location.path('/');
    }
  })
}]);
```

#### Manipulate a Template

The edit link in the template below will be shown, because the current user is a `user`, and `Post` which was created by our user is one of a his role's abilities.

###### Controller

```js
app.controller('DemoCtrl', ['$scope', 'AclService', function ($scope, AclService) {
    $scope.can = AclService.can;
    $scope.post = {
        id: 1,
        authorId: 1,
        name: 'Demo post',
        getResourceId: function () { //AclResourceInterface implementation
            return 'Post';
        }
    };
}]);
```

###### Template

```html
<h1>{{ post.name }}</h1>
<a ng-href="posts/{{ post.id }}/edit" ng-show="can(post, 'edit')">Edit</a>
```

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
