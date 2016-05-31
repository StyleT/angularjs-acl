'use strict';

describe('ncAclService', function () {
    /** @type {AclService} */
    var AclService;

    beforeEach(module('ng-acl'));

    beforeEach(inject(function (_AclService_) {
        AclService = _AclService_;
    }));


    it('tests basic resource inheritance', function () {
        AclService
            .addResource('city')
            .addResource('building', 'city')
            .addResource('room', 'building');

        expect(AclService.inheritsResource('building', 'city', true)).toBeTruthy();
        expect(AclService.inheritsResource('room', 'building', true)).toBeTruthy();
        expect(AclService.inheritsResource('room', 'city')).toBeTruthy();
        expect(AclService.inheritsResource('room', 'city', true)).toBeFalsy();
        expect(AclService.inheritsResource('city', 'building')).toBeFalsy();
        expect(AclService.inheritsResource('building', 'room')).toBeFalsy();
        expect(AclService.inheritsResource('city', 'room')).toBeFalsy();

        AclService.removeResource('building');
        expect(AclService.hasResource('room')).toBeFalsy();
    });
});