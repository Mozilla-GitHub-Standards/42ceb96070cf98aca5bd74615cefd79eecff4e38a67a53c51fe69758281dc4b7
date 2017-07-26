/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict'

const assert = require('insist')
var uuid = require('uuid')
var crypto = require('crypto')
var base64url = require('base64url')
const sinon = require('sinon')
var proxyquire = require('proxyquire')

const log = { trace () {}, info () {}, error () {} }

var config = require('../../config').getProperties()
var P = require('../../lib/promise')
var UnblockCode = require('../../lib/crypto/base32')(config.signinUnblock.codeLength)
var TestServer = require('../test_server')
const lastAccessTimeUpdates = {
  enabled: true,
  enabledEmailAddresses: /.*/,
  sampleRate: 1
}
const Token = require('../../lib/tokens')(log, {
  lastAccessTimeUpdates: lastAccessTimeUpdates,
  tokenLifetimes: {
    sessionTokenWithoutDevice: 2419200000
  }
})
const redisGetSpy = sinon.stub()
const redisSetSpy = sinon.stub()
const redisDelSpy = sinon.stub()
const getGeoDataSpy = sinon.stub()
getGeoDataSpy.returns(P.resolve({}))

const DB = proxyquire('../../lib/db', {
  '../lib/geodb': () => getGeoDataSpy,
  redis: {
    createClient: () => ({
      getAsync: redisGetSpy,
      setAsync: redisSetSpy,
      del: redisDelSpy
    })
  }
})({
  lastAccessTimeUpdates,
  signinCodeSize: config.signinCodeSize,
  redis: { enabled: true },
  tokenLifetimes: {}
},
  log,
  Token,
  UnblockCode
)

var zeroBuffer16 = Buffer('00000000000000000000000000000000', 'hex').toString('hex')
var zeroBuffer32 = Buffer('0000000000000000000000000000000000000000000000000000000000000000', 'hex').toString('hex')

let account, secondEmail

describe('remote db', function() {
  this.timeout(20000)
  let dbServer, db
  before(() => {
    return TestServer.start(config)
      .then(s => {
        dbServer = s
        return DB.connect(config[config.db.backend])
      })
      .then(x => {
        db = x
      })
  })

  beforeEach(() => {
    account = {
      uid: uuid.v4('binary').toString('hex'),
      email: dbServer.uniqueEmail(),
      emailCode: zeroBuffer16,
      emailVerified: false,
      verifierVersion: 1,
      verifyHash: zeroBuffer32,
      authSalt: zeroBuffer32,
      kA: zeroBuffer32,
      wrapWrapKb: zeroBuffer32,
      tokenVerificationId: zeroBuffer16
    }

    return db.createAccount(account)
      .then((account) => {
        assert.deepEqual(account.uid, account.uid, 'account.uid is the same as the input account.uid')

        secondEmail = dbServer.uniqueEmail()
        const emailData = {
          email: secondEmail,
          emailCode: crypto.randomBytes(16).toString('hex'),
          normalizedEmail: secondEmail.toLowerCase(),
          isVerified: true,
          isPrimary: false,
          uid: account.uid
        }
        return db.createEmail(account.uid, emailData)
      })
  })

  it(
    'ping',
    () => {
      return db.ping()
    }
  )

  it(
    'account creation',
    () => {
      return db.accountExists(account.email)
        .then(function(exists) {
          assert.ok(exists, 'account exists for this email address')
        })
        .then(function() {
          return db.account(account.uid)
        })
        .then(function(account) {
          assert.deepEqual(account.uid, account.uid, 'uid')
          assert.equal(account.email, account.email, 'email')
          assert.deepEqual(account.emailCode, account.emailCode, 'emailCode')
          assert.equal(account.emailVerified, account.emailVerified, 'emailVerified')
          assert.deepEqual(account.kA, account.kA, 'kA')
          assert.deepEqual(account.wrapWrapKb, account.wrapWrapKb, 'wrapWrapKb')
          assert(! account.verifyHash, 'verifyHash')
          assert.deepEqual(account.authSalt, account.authSalt, 'authSalt')
          assert.equal(account.verifierVersion, account.verifierVersion, 'verifierVersion')
          assert.ok(account.createdAt, 'createdAt')
        })
    }
  )

  it(
    'session token handling',
    () => {
      var tokenId
      return db.sessions(account.uid)
        .then(function(sessions) {
          assert.ok(Array.isArray(sessions), 'sessions is array')
          assert.equal(sessions.length, 0, 'sessions is empty')
          return db.emailRecord(account.email)
        })
        .then(function(emailRecord) {
          emailRecord.createdAt = Date.now()
          emailRecord.tokenVerificationId = account.tokenVerificationId
          return db.createSessionToken(emailRecord, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:41.0) Gecko/20100101 Firefox/41.0')
        })
        .then(function(sessionToken) {
          assert.deepEqual(sessionToken.uid, account.uid)
          tokenId = sessionToken.tokenId
          redisGetSpy.returns(P.resolve(null))
          return db.sessions(account.uid)
        })
        .then(function(sessions) {
          assert.equal(sessions.length, 1, 'sessions contains one item')
          assert.equal(Object.keys(sessions[0]).length, 16, 'session has correct number of properties')
          assert.equal(typeof sessions[0].tokenId, 'string', 'tokenId property is not a buffer')
          assert.equal(sessions[0].uid, account.uid, 'uid property is correct')
          assert.ok(sessions[0].createdAt >= account.createdAt, 'createdAt property seems correct')
          assert.equal(sessions[0].uaBrowser, 'Firefox', 'uaBrowser property is correct')
          assert.equal(sessions[0].uaBrowserVersion, '41', 'uaBrowserVersion property is correct')
          assert.equal(sessions[0].uaOS, 'Mac OS X', 'uaOS property is correct')
          assert.equal(sessions[0].uaOSVersion, '10.10', 'uaOSVersion property is correct')
          assert.equal(sessions[0].uaDeviceType, null, 'uaDeviceType property is correct')
          assert.equal(sessions[0].lastAccessTime, sessions[0].createdAt, 'lastAccessTime property is correct')
          return db.sessionToken(tokenId)
        })
        .then(sessionToken => {
          assert.equal(sessionToken.tokenId, tokenId, 'token id matches')
          assert.equal(sessionToken.uaBrowser, 'Firefox')
          assert.equal(sessionToken.uaBrowserVersion, '41')
          assert.equal(sessionToken.uaOS, 'Mac OS X')
          assert.equal(sessionToken.uaOSVersion, '10.10')
          assert.equal(sessionToken.uaDeviceType, null)
          assert.equal(sessionToken.lastAccessTime, sessionToken.createdAt)
          assert.equal(sessionToken.uid, account.uid)
          assert.equal(sessionToken.email, account.email)
          assert.equal(sessionToken.emailCode, account.emailCode)
          assert.equal(sessionToken.emailVerified, account.emailVerified)
          assert.equal(sessionToken.lifetime < Infinity, true)
          return sessionToken
        })
        .then(function(sessionToken) {
          // override lastAccessTimeUpdates flag
          lastAccessTimeUpdates.enabled = false
          return db.updateSessionToken(sessionToken)
        })
        .then(function(result) {
          assert.equal(undefined, result)
          assert.equal(redisSetSpy.lastCall, null, 'session token was not updated if lastAccessTimeUpdates flag is false')
          // reset lastAccessTimeUpdates flag
          lastAccessTimeUpdates.enabled = true
          return db.sessionToken(tokenId)
        })
        .then(function(sessionToken) {
          getGeoDataSpy.returns(P.resolve({location: {state: 'Mordor', country: 'ME'}}))
          return db.updateSessionToken(sessionToken, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:41.0) Gecko/20100101 Firefox/41.0', '1.1.1.1')
        })
        .then(function(sessionTokens) {
          assert.equal(redisSetSpy.lastCall.args[0], account.uid)

          const redisSetArgs = JSON.parse(redisSetSpy.lastCall.args[1])
          const token = redisSetArgs[0]
          assert.equal(token.tokenId, tokenId)
          assert.equal(token.uid, account.uid)
          assert.equal(token.uaBrowser, 'Firefox')
          assert.equal(token.uaBrowserVersion, '41')
          assert.equal(token.uaOS, 'Mac OS X')
          assert.equal(token.uaOSVersion, '10.10')
          assert.equal(token.location.state, 'Mordor', 'state is correct')
          assert.equal(token.location.country, 'ME', 'country is correct')
          assert.ok(token.lastAccessTime)
          assert.ok(token.createdAt)
          return db.sessionToken(tokenId)
        })
        .then(function(sessionToken) {
          getGeoDataSpy.returns(P.reject())
          return db.updateSessionToken(sessionToken, 'Mozilla/5.0 (Android 4.4; Mobile; rv:41.0) Gecko/41.0 Firefox/41.0', '1.1.1.1')
        })
        .then(function(tokens) {
          redisGetSpy.returns(P.resolve(JSON.stringify(tokens)))
          return db.sessions(account.uid)
        })
        .then(function(sessions) {
          assert.equal(sessions.length, 1, 'sessions still contains one item')
          assert.equal(sessions[0].uaBrowser, 'Firefox Mobile', 'uaBrowser property is correct')
          assert.equal(sessions[0].uaBrowserVersion, '41', 'uaBrowserVersion property is correct')
          assert.equal(sessions[0].uaOS, 'Android', 'uaOS property is correct')
          assert.equal(sessions[0].uaOSVersion, '4.4', 'uaOSVersion property is correct')
          assert.equal(sessions[0].uaDeviceType, 'mobile', 'uaDeviceType property is correct')
          assert.equal(sessions[0].location, null, 'location property is correct')
          return db.sessionToken(tokenId)
        })
        .then(function(sessionToken) {
          // this returns previously stored data since sessionToken doesnt read from cache
          assert.equal(sessionToken.uaBrowser, 'Firefox')
          assert.equal(sessionToken.uaBrowserVersion, '41')
          assert.equal(sessionToken.uaOS, 'Mac OS X')
          assert.equal(sessionToken.uaOSVersion, '10.10')
          assert.ok(sessionToken.lastAccessTime >= sessionToken.createdAt)
          assert.ok(sessionToken.lastAccessTime <= Date.now())
          return sessionToken
        })
        .then(function(sessionToken) {
          const mockTokens = JSON.stringify([{
            uid: sessionToken.uid,
            id: 'idToNotDelete'
          }, {
            uid: sessionToken.uid,
            id: sessionToken.id
          }])
          redisGetSpy.returns(P.resolve(mockTokens))
          return db.deleteSessionToken(sessionToken)
        })
        .then(function() {
          const redisSetArgs = JSON.parse(redisSetSpy.lastCall.args[1])
          assert.equal(redisSetArgs.length, 1)
          assert.equal(redisSetArgs[0].id, 'idToNotDelete')

          return db.sessionToken(tokenId)
          .then(function(sessionToken) {
            assert(false, 'The above sessionToken() call should fail, since the sessionToken has been deleted')
          }, function(err) {
            assert.equal(err.errno, 110, 'sessionToken() fails with the correct error code')
            var msg = 'Error: The authentication token could not be found'
            assert.equal(msg, '' + err, 'sessionToken() fails with the correct message')
          })
        })
    }
  )

  it(
    'device registration',
    () => {
      redisGetSpy.returns(P.resolve(null))
      let sessionToken, anotherSessionToken
      const deviceInfo = {
        id: crypto.randomBytes(16).toString('hex'),
        name: '',
        type: 'mobile',
        pushCallback: 'https://foo/bar',
        pushPublicKey: base64url(Buffer.concat([Buffer.from('\x04'), crypto.randomBytes(64)])),
        pushAuthKey: base64url(crypto.randomBytes(16))
      }
      const conflictingDeviceInfo = {
        id: crypto.randomBytes(16).toString('hex'),
        name: 'wibble'
      }
      return db.emailRecord(account.email)
          .then(function (emailRecord) {
            emailRecord.tokenVerificationId = account.tokenVerificationId
            // Create a session token
            return db.createSessionToken(emailRecord, 'Mozilla/5.0 (Android 4.4; Mobile; rv:41.0) Gecko/41.0 Firefox/41.0')
          })
          .then(function (result) {
            sessionToken = result
            // Attempt to update a non-existent device
            return db.updateDevice(account.uid, sessionToken.tokenId, deviceInfo)
              .then(function () {
                assert(false, 'updating a non-existent device should have failed')
              }, function (err) {
                assert.equal(err.errno, 123, 'err.errno === 123')
              })
          })
          .then(function () {
            // Attempt to delete a non-existent device
            return db.deleteDevice(account.uid, deviceInfo.id)
              .then(function () {
                assert(false, 'deleting a non-existent device should have failed')
              }, function (err) {
                assert.equal(err.errno, 123, 'err.errno === 123')
              })
          })
          .then(function () {
            // Fetch all of the devices for the account
            return db.devices(account.uid)
              .catch(function () {
                assert(false, 'getting devices should not have failed')
              })
          })
          .then(function (devices) {
            assert.ok(Array.isArray(devices), 'devices is array')
            assert.equal(devices.length, 0, 'devices array is empty')
            // Create a device
            return db.createDevice(account.uid, sessionToken.tokenId, deviceInfo)
              .catch(function (err) {
                assert(false, 'adding a new device should not have failed')
              })
          })
          .then(function (device) {
            assert.ok(device.id, 'device.id is set')
            assert.ok(device.createdAt > 0, 'device.createdAt is set')
            assert.equal(device.name, deviceInfo.name, 'device.name is correct')
            assert.equal(device.type, deviceInfo.type, 'device.type is correct')
            assert.equal(device.pushCallback, deviceInfo.pushCallback, 'device.pushCallback is correct')
            assert.equal(device.pushPublicKey, deviceInfo.pushPublicKey, 'device.pushPublicKey is correct')
            assert.equal(device.pushAuthKey, deviceInfo.pushAuthKey, 'device.pushAuthKey is correct')
            // Fetch the session token
            return db.sessionToken(sessionToken.tokenId)
          })
          .then(sessionToken => {
            assert.equal(sessionToken.lifetime, Infinity)
            // Attempt to create a device with a duplicate session token
            return db.createDevice(account.uid, sessionToken.tokenId, conflictingDeviceInfo)
              .then(function () {
                assert(false, 'adding a device with a duplicate session token should have failed')
              }, function (err) {
                assert.equal(err.errno, 124, 'err.errno')
                assert.equal(err.output.payload.deviceId, deviceInfo.id)
              })
          })
          .then(function () {
            // Fetch all of the devices for the account
            return db.devices(account.uid)
          })
          .then(function (devices) {
            assert.equal(devices.length, 1, 'devices array contains one item')
            return devices[0]
          })
          .then(function (device) {
            assert.ok(device.id, 'device.id is set')
            assert.ok(device.lastAccessTime > 0, 'device.lastAccessTime is set')
            assert.equal(device.name, deviceInfo.name, 'device.name is correct')
            assert.equal(device.type, deviceInfo.type, 'device.type is correct')
            assert.equal(device.pushCallback, deviceInfo.pushCallback, 'device.pushCallback is correct')
            assert.equal(device.pushPublicKey, deviceInfo.pushPublicKey, 'device.pushPublicKey is correct')
            assert.equal(device.pushAuthKey, deviceInfo.pushAuthKey, 'device.pushAuthKey is correct')
            assert.equal(device.uaBrowser, 'Firefox Mobile', 'device.uaBrowser is correct')
            assert.equal(device.uaBrowserVersion, '41', 'device.uaBrowserVersion is correct')
            assert.equal(device.uaOS, 'Android', 'device.uaOS is correct')
            assert.equal(device.uaOSVersion, '4.4', 'device.uaOSVersion is correct')
            assert.equal(device.uaDeviceType, 'mobile', 'device.uaDeviceType is correct')
            deviceInfo.id = device.id
            deviceInfo.name = 'wibble'
            deviceInfo.type = 'desktop'
            deviceInfo.pushCallback = ''
            deviceInfo.pushPublicKey = ''
            deviceInfo.pushAuthKey = ''
            // Update the device and the session token
            getGeoDataSpy.returns(P.resolve({location: {state: 'Mordor', country: 'ME'}}))
            return P.all([
              db.updateDevice(account.uid, sessionToken.tokenId, deviceInfo),
              db.updateSessionToken(sessionToken, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:44.0) Gecko/20100101 Firefox/44.0')
            ])
              .catch(function (err) {
                assert(false, 'updating a new device or existing session token should not have failed')
              })
          })
          .then(results => {
            redisGetSpy.returns(P.resolve(JSON.stringify(results[1])))

            // Create another session token
            return db.createSessionToken(sessionToken, 'Mozilla/5.0 (Android 7.1.2; Mobile; rv:56.0) Gecko/56.0 Firefox/56.0')
          })
          .then(result =>{
            anotherSessionToken = result
            // Create another device
            return db.createDevice(account.uid, anotherSessionToken.tokenId, conflictingDeviceInfo)
          })
          .then(() =>{
            // Attempt to update a device with a duplicate session token
            return db.updateDevice(account.uid, anotherSessionToken.tokenId, deviceInfo)
              .then(function () {
                assert(false, 'updating a device with a duplicate session token should have failed')
              }, function (err) {
                assert.equal(err.errno, 124, 'err.errno')
                assert.equal(err.output.payload.deviceId, conflictingDeviceInfo.id)
              })
          })
          .then(() =>{
            // Fetch all of the devices for the account
            return db.devices(account.uid)
          })
          .then(function (devices) {
            assert.equal(devices.length, 2, 'devices array contains two items')

            if (devices[0].id === deviceInfo.id) {
              return devices[0]
            }

            return devices[1]
          })
          .then(function (device) {
            assert.ok(device.lastAccessTime > 0, 'device.lastAccessTime is set')
            assert.equal(device.name, deviceInfo.name, 'device.name is correct')
            assert.equal(device.type, deviceInfo.type, 'device.type is correct')
            assert.equal(device.pushCallback, deviceInfo.pushCallback, 'device.pushCallback is correct')
            assert.equal(device.pushPublicKey, '', 'device.pushPublicKey is correct')
            assert.equal(device.pushAuthKey, '', 'device.pushAuthKey is correct')
            assert.equal(device.uaBrowser, 'Firefox', 'device.uaBrowser is correct')
            assert.equal(device.uaBrowserVersion, '44', 'device.uaBrowserVersion is correct')
            assert.equal(device.uaOS, 'Mac OS X', 'device.uaOS is correct')
            assert.equal(device.uaOSVersion, '10.10', 'device.uaOSVersion is correct')
            assert.equal(device.uaDeviceType, null, 'device.uaDeviceType is correct')
            // Delete the devices
            return P.all([
              db.deleteDevice(account.uid, deviceInfo.id),
              db.deleteDevice(account.uid, conflictingDeviceInfo.id)
            ])
              .catch(function () {
                assert(false, 'deleting a device should not have failed')
              })
          })
          .then(function () {
            // Fetch all of the devices for the account
            return db.devices(account.uid)
          })
          .then(function (devices) {
            assert.equal(devices.length, 0, 'devices array is empty')
          })
    }
  )

  it(
    'keyfetch token handling',
    () => {
      var tokenId
      return db.emailRecord(account.email)
        .then(function(emailRecord) {
          return db.createKeyFetchToken({
            uid: emailRecord.uid,
            kA: emailRecord.kA,
            wrapKb: account.wrapWrapKb
          })
        })
        .then(function(keyFetchToken) {
          assert.deepEqual(keyFetchToken.uid, account.uid)
          tokenId = keyFetchToken.tokenId
        })
        .then(function() {
          return db.keyFetchToken(tokenId)
        })
        .then(function(keyFetchToken) {
          assert.deepEqual(keyFetchToken.tokenId, tokenId, 'token id matches')
          assert.deepEqual(keyFetchToken.uid, account.uid)
          assert.equal(keyFetchToken.emailVerified, account.emailVerified)
          return keyFetchToken
        })
        .then(function(keyFetchToken) {
          return db.deleteKeyFetchToken(keyFetchToken)
        })
        .then(function() {
          return db.keyFetchToken(tokenId)
        })
        .then(function(keyFetchToken) {
          assert(false, 'The above keyFetchToken() call should fail, since the keyFetchToken has been deleted')
        }, function(err) {
          assert.equal(err.errno, 110, 'keyFetchToken() fails with the correct error code')
          var msg = 'Error: The authentication token could not be found'
          assert.equal(msg, '' + err, 'keyFetchToken() fails with the correct message')
        })
    }
  )

  it(
    'reset token handling',
    () => {
      var tokenId
      return db.emailRecord(account.email)
        .then(function(emailRecord) {
          return db.createPasswordForgotToken(emailRecord)
        })
        .then(function(passwordForgotToken) {
          return db.forgotPasswordVerified(passwordForgotToken)
            .then(accountResetToken => {
              assert.ok(accountResetToken.createdAt > passwordForgotToken.createdAt, 'account reset token should be newer than password forgot token')
              return accountResetToken
            })
        })
        .then(function(accountResetToken) {
          assert.deepEqual(accountResetToken.uid, account.uid, 'account reset token uid should be the same as the account.uid')
          tokenId = accountResetToken.tokenId
        })
        .then(function() {
          return db.accountResetToken(tokenId)
        })
        .then(function(accountResetToken) {
          assert.deepEqual(accountResetToken.tokenId, tokenId, 'token id matches')
          assert.deepEqual(accountResetToken.uid, account.uid, 'account reset token uid should still be the same as the account.uid')
          return accountResetToken
        })
        .then(function(accountResetToken) {
          return db.deleteAccountResetToken(accountResetToken)
        })
        .then(function() {
          return db.accountResetToken(tokenId)
        })
        .then(function(accountResetToken) {
          assert(false, 'The above accountResetToken() call should fail, since the accountResetToken has been deleted')
        }, function(err) {
          assert.equal(err.errno, 110, 'accountResetToken() fails with the correct error code')
          var msg = 'Error: The authentication token could not be found'
          assert.equal(msg, '' + err, 'accountResetToken() fails with the correct message')
        })
    }
  )

  it(
    'forgotpwd token handling',
    () => {
      var token1
      var token1tries = 0
      return db.emailRecord(account.email)
        .then(function(emailRecord) {
          return db.createPasswordForgotToken(emailRecord)
        })
        .then(function(passwordForgotToken) {
          assert.deepEqual(passwordForgotToken.uid, account.uid, 'passwordForgotToken uid same as account.uid')
          token1 = passwordForgotToken
          token1tries = token1.tries
        })
        .then(function() {
          return db.passwordForgotToken(token1.tokenId)
        })
        .then(function(passwordForgotToken) {
          assert.deepEqual(passwordForgotToken.tokenId, token1.tokenId, 'token id matches')
          assert.deepEqual(passwordForgotToken.uid, token1.uid, 'tokens are identical')
          return passwordForgotToken
        })
        .then(function(passwordForgotToken) {
          passwordForgotToken.tries -= 1
          return db.updatePasswordForgotToken(passwordForgotToken)
        })
        .then(function() {
          return db.passwordForgotToken(token1.tokenId)
        })
        .then(function(passwordForgotToken) {
          assert.deepEqual(passwordForgotToken.tokenId, token1.tokenId, 'token id matches again')
          assert.equal(passwordForgotToken.tries, token1tries - 1, '')
          return passwordForgotToken
        })
        .then(function(passwordForgotToken) {
          return db.deletePasswordForgotToken(passwordForgotToken)
        })
        .then(function() {
          return db.passwordForgotToken(token1.tokenId)
        })
        .then(function(passwordForgotToken) {
          assert(false, 'The above passwordForgotToken() call should fail, since the passwordForgotToken has been deleted')
        }, function(err) {
          assert.equal(err.errno, 110, 'passwordForgotToken() fails with the correct error code')
          var msg = 'Error: The authentication token could not be found'
          assert.equal(msg, '' + err, 'passwordForgotToken() fails with the correct message')
        })
    }
  )

  it(
    'email verification',
    () => {
      return db.emailRecord(account.email)
        .then(function(emailRecord) {
          return db.verifyEmail(emailRecord, emailRecord.emailCode)
        })
        .then(function() {
          return db.account(account.uid)
        })
        .then(function(account) {
          assert.ok(account.emailVerified, 'account should now be emailVerified')
        })
    }
  )

  it(
    'db.forgotPasswordVerified',
    () => {
      var token1
      return db.emailRecord(account.email)
        .then(function(emailRecord) {
          return db.createPasswordForgotToken(emailRecord)
        })
        .then(function(passwordForgotToken) {
          return db.forgotPasswordVerified(passwordForgotToken)
        })
        .then(function(accountResetToken) {
          assert.deepEqual(accountResetToken.uid, account.uid, 'uid is the same as account.uid')
          token1 = accountResetToken
        })
        .then(function() {
          return db.accountResetToken(token1.tokenId)
        })
        .then(function(accountResetToken) {
          assert.deepEqual(accountResetToken.uid, account.uid)
          return db.deleteAccountResetToken(token1)
        })
    }
  )

  it(
    'db.resetAccount',
    () => {
      return db.emailRecord(account.email)
        .then(function(emailRecord) {
          emailRecord.tokenVerificationId = account.tokenVerificationId
          return db.createSessionToken(emailRecord, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:41.0) Gecko/20100101 Firefox/41.0')
        })
        .then(function(sessionToken) {
          return db.forgotPasswordVerified(sessionToken)
        })
        .then(function(accountResetToken) {
          return db.resetAccount(accountResetToken, account)
        })
        .then(function() {
          assert.equal(redisDelSpy.lastCall.args[0], account.uid)
          redisDelSpy.reset()
          // account should STILL exist for this email address
          return db.accountExists(account.email)
        })
        .then(function(exists) {
          assert.equal(exists, true, 'account should still exist')
        })
    }
  )

  it(
    'db.securityEvent',
    () => {
      return db.securityEvent({
        ipAddr: '127.0.0.1',
        name: 'account.create',
        uid: account.uid
      })
      .then(function(resp) {
        assert.equal(typeof resp, 'object')
        assert.equal(Object.keys(resp).length, 0)

        return db.securityEvent({
          ipAddr: '127.0.0.1',
          name: 'account.login',
          uid: account.uid
        })
      })
      .then(function(resp) {
        assert.equal(typeof resp, 'object')
        assert.equal(Object.keys(resp).length, 0)
      })
    }
  )

  it(
    'db.securityEvents',
    () => {
      return db.securityEvent({
        ipAddr: '127.0.0.1',
        name: 'account.create',
        uid: account.uid
      })
      .then(() => {
        return db.securityEvents({
          ipAddr: '127.0.0.1',
          uid: account.uid
        })
      })
      .then(function (events) {
        assert.equal(events.length, 1)
      })
    }
  )

  it(
    'unblock code',
    () => {
      var unblockCode
      return db.createUnblockCode(account.uid)
        .then(function(_unblockCode) {
          assert.ok(_unblockCode)
          unblockCode = _unblockCode

          return db.consumeUnblockCode(account.uid, 'NOTREAL')
        })
        .then(
          function () {
            assert(false, 'consumeUnblockCode() with an invalid unblock code should not succeed')
          },
          function (err) {
            assert.equal(err.errno, 127, 'consumeUnblockCode() fails with the correct error code')
            var msg = 'Error: Invalid unblock code'
            assert.equal(msg, '' + err, 'consumeUnblockCode() fails with the correct message')
          }
        )
        .then(
          function() {
            return db.consumeUnblockCode(account.uid, unblockCode)
          }
        )
        .then(
          function() {
            // re-use unblock code, no longer valid
            return db.consumeUnblockCode(account.uid, unblockCode)
          }, function (err) {
            assert(false, 'consumeUnblockCode() with a valid unblock code should succeed')
          }
        )
        .then(
          function () {
            assert(false, 'consumeUnblockCode() with an invalid unblock code should not succeed')
          },
          function (err) {
            assert.equal(err.errno, 127, 'consumeUnblockCode() fails with the correct error code')
            var msg = 'Error: Invalid unblock code'
            assert.equal(msg, '' + err, 'consumeUnblockCode() fails with the correct message')
          }
        )
    }
  )

  it('signinCodes', () => {
    let previousCode
    const flowId = crypto.randomBytes(32).toString('hex')

    // Create a signinCode without a flowId
    return db.createSigninCode(account.uid)
      .then(code => {
        assert.equal(typeof code, 'string', 'db.createSigninCode should return a string')
        assert.equal(Buffer.from(code, 'hex').length, config.signinCodeSize, 'db.createSigninCode should return the correct size code')

        previousCode = code

        // Stub crypto.randomBytes to return a duplicate code
        sinon.stub(crypto, 'randomBytes', (size, callback) => {
          // Reinstate the real crypto.randomBytes after we've returned a duplicate
          crypto.randomBytes.restore()

          if (! callback) {
            return previousCode
          }

          callback(null, previousCode)
        })

        // Create a signinCode with crypto.randomBytes rigged to return a duplicate,
        // and this time specifying a flowId
        return db.createSigninCode(account.uid, flowId)
      })
      .then(code => {
        assert.equal(typeof code, 'string', 'db.createSigninCode should return a string')
        assert.notEqual(code, previousCode, 'db.createSigninCode should not return a duplicate code')
        assert.equal(Buffer.from(code, 'hex').length, config.signinCodeSize, 'db.createSigninCode should return the correct size code')

        // Consume both signinCodes
        return P.all([
          db.consumeSigninCode(previousCode),
          db.consumeSigninCode(code)
        ])
      })
      .then(results => {
        assert.equal(results[0].email, account.email, 'db.consumeSigninCode should return the email address')
        assert.equal(results[1].email, account.email, 'db.consumeSigninCode should return the email address')
        if (results[1].flowId) {
          // This assertion is conditional so that tests pass regardless of db version
          assert.equal(results[1].flowId, flowId, 'db.consumeSigninCode should return the flowId')
        }

        // Attempt to consume a consumed signinCode
        return db.consumeSigninCode(previousCode)
          .then(() => assert.fail('db.consumeSigninCode should have failed'))
          .catch(err => {
            assert.equal(err.errno, 146, 'db.consumeSigninCode should fail with errno 146')
            assert.equal(err.message, 'Invalid signin code', 'db.consumeSigninCode should fail with message "Invalid signin code"')
            assert.equal(err.output.statusCode, 400, 'db.consumeSigninCode should fail with status 400')
          })
      })
  })

  it(
    'account deletion',
    () => {
      return db.emailRecord(account.email)
        .then(function(emailRecord) {
          assert.deepEqual(emailRecord.uid, account.uid, 'retrieving uid should be the same')
          return db.deleteAccount(emailRecord)
        })
        .then(function() {
          assert.equal(redisDelSpy.lastCall.args[0], account.uid)
          redisDelSpy.reset()
          // account should no longer exist for this email address
          return db.accountExists(account.email)
        })
        .then(function(exists) {
          assert.equal(exists, false, 'account should no longer exist')
        })
    }
  )

  describe('account record', () => {
    it('can retrieve account from account email', () => {
      return P.all([db.emailRecord(account.email), db.accountRecord(account.email)])
        .spread(function (emailRecord, accountRecord) {
          assert.equal(emailRecord.email, accountRecord.email, 'original account and email records should be equal')
          assert.deepEqual(emailRecord.emails, accountRecord.emails, 'emails should be equal')
          assert.deepEqual(emailRecord.primaryEmail, accountRecord.primaryEmail, 'primary emails should be equal')
        })
    })

    it('can retrieve account from secondary email', () => {
      return P.all([db.accountRecord(account.email), db.accountRecord(secondEmail)])
        .spread(function (accountRecord, accountRecordFromSecondEmail) {
          assert.equal(accountRecordFromSecondEmail.email, accountRecord.email, 'original account and email records should be equal')
          assert.deepEqual(accountRecordFromSecondEmail.emails, accountRecord.emails, 'emails should be equal')
          assert.deepEqual(accountRecordFromSecondEmail.primaryEmail, accountRecord.primaryEmail, 'primary emails should be equal')
        })
    })

    it('returns unknown account', () => {
      return db.accountRecord('idontexist@email.com')
        .then(function () {
          assert.fail('should not have retrieved non-existent account')
        })
        .catch((err) => {
          assert.equal(err.errno, 102, 'unknown account error code')
        })
    })
  })

  describe('set primary email', () => {
    it('can set primary email address', () => {
      return db.setPrimaryEmail(account.uid, secondEmail)
        .then(function (res) {
          assert.ok(res, 'ok response')
          return db.accountRecord(secondEmail)
        })
        .then(function (accountRecord) {
          assert.equal(accountRecord.primaryEmail.email, secondEmail, 'primary email set')
        })
    })
  })

  after(() => {
    return TestServer.stop(dbServer)
      .then(() => {
        return db && db.close()
      })
  })
})
