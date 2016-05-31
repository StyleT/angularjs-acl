'use strict';

module.exports = angular.module('ng-acl', [])
	.service('AclService', require('js-acl'));