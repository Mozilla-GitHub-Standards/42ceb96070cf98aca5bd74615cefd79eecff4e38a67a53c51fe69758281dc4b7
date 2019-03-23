/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict'

const ScopeSet = require('fxa-shared').oauth.scopes

// right now we only care about notifications for the following scopes
// if not a match, then we don't notify
const NOTIFICATION_SCOPES = ScopeSet.fromArray(['https://identity.mozilla.com/apps/oldsync'])

module.exports = {
  newTokenNotification: async function newTokenNotification (db, oauthdb, mailer, devices, request, credentials, grant) {
    const scopeSet = ScopeSet.fromString(grant.scope)

    if (! scopeSet.intersects(NOTIFICATION_SCOPES)) {
      // right now we only care about notifications for the `oldsync` scope
      // if not a match, then we don't do any notifications
      return
    }

    const tokenVerify = await oauthdb.checkAccessToken({
      token: grant.access_token
    })

    if (! credentials) {
      credentials = {}
    }

    const uid = tokenVerify.user
    credentials.uid = uid
    credentials.tokenVerified = true // XXX TODO: check this?
    credentials.refreshTokenId = grant.refresh_token
    credentials.client = await oauthdb.getClientInfo(tokenVerify.client_id)

    await devices.upsert(request, credentials, {})

    const geoData = request.app.geo
    const ip = request.app.clientAddress
    const service = request.payload.service || request.query.service || tokenVerify.client_id

    const emailOptions = {
      acceptLanguage: request.app.acceptLanguage,
      ip: ip,
      location: geoData.location,
      service: service,
      timeZone: geoData.timeZone,
      uid: credentials.uid
    }

    const account = await db.account(uid)
    await mailer.sendNewDeviceLoginNotification(account.emails, account, emailOptions)
  }
}
