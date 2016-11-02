'use strict'
const url = require('url')
const qs = require('querystring')
const EventEmitter = require('events').EventEmitter
const request = require('request')
const crypto = require('crypto')

class Bot extends EventEmitter {
  constructor (opts) {
    super()

    opts = opts || {}

    this.app_secret = opts.app_secret || false
    this.verify_token = opts.verify || false
    this.debug = opts.debug || false
  }

  getProfile (accessToken, id, cb) {
    if (!cb) cb = Function.prototype

    request({
      method: 'GET',
      uri: `https://graph.facebook.com/v2.6/${id}`,
      qs: this._getQs({ access_token: accessToken, fields: 'first_name,last_name,profile_pic,locale,timezone,gender' }),
      json: true
    }, (err, res, body) => {
      if (err) return cb(err)
      if (body.error) return cb(body.error)

      if (cb) cb(null, body)
    })
  }

  sendMessage (recipient, accessToken, payload, cb) {
    if (!cb) cb = Function.prototype

    request({
      method: 'POST',
      uri: 'https://graph.facebook.com/v2.6/me/messages',
      qs: this._getQs({ access_token: accessToken }),
      json: {
        recipient: { id: recipient },
        message: payload
      }
    }, (err, res, body) => {
      if (err) return cb(err)
      if (body.error) return cb(body.error)

      if (cb) cb(null, body)
    })
  }

  sendSenderAction (recipient, accessToken, senderAction, cb) {
    if (!cb) cb = Function.prototype

    request({
      method: 'POST',
      uri: 'https://graph.facebook.com/v2.6/me/messages',
      qs: this._getQs({ access_token: accessToken }),
      json: {
        recipient: {
          id: recipient
        },
        sender_action: senderAction
      }
    }, (err, res, body) => {
      if (err) return cb(err)
      if (body.error) return cb(body.error)

      if (cb) cb(null, body)
    })
  }

  setThreadSettings (accessToken, threadState, callToActions, cb) {
    if (!cb) cb = Function.prototype

    request({
      method: 'POST',
      uri: 'https://graph.facebook.com/v2.6/me/thread_settings',
      qs: this._getQs({ access_token: accessToken }),
      json: {
        setting_type: 'call_to_actions',
        thread_state: threadState,
        call_to_actions: callToActions
      }
    }, (err, res, body) => {
      if (err) return cb(err)
      if (body.error) return cb(body.error)

      if (cb) cb(null, body)
    })
  }

  removeThreadSettings (accessToken, threadState, cb) {
    if (!cb) cb = Function.prototype

    request({
      method: 'DELETE',
      uri: 'https://graph.facebook.com/v2.6/me/thread_settings',
      qs: this._getQs({ access_token: accessToken }),
      json: {
        setting_type: 'call_to_actions',
        thread_state: threadState
      }
    }, (err, res, body) => {
      if (err) return cb(err)
      if (body.error) return cb(body.error)

      if (cb) cb(null, body)
    })
  }

  setGetStartedButton (accessToken, payload, cb) {
    if (!cb) cb = Function.prototype

    return this.setThreadSettings(accessToken, 'new_thread', payload, cb)
  }

  setPersistentMenu (accessToken, payload, cb) {
    if (!cb) cb = Function.prototype

    return this.setThreadSettings(accessToken, 'existing_thread', payload, cb)
  }

  removeGetStartedButton (accessToken, cb) {
    if (!cb) cb = Function.prototype

    return this.removeThreadSettings(accessToken, 'new_thread', cb)
  }

  removePersistentMenu (accessToken, cb) {
    if (!cb) cb = Function.prototype

    return this.removeThreadSettings(accessToken, 'existing_thread', cb)
  }

  middleware () {
    return (req, res) => {
      // we always write 200, otherwise facebook will keep retrying the request
      res.writeHead(200, { 'Content-Type': 'application/json' })
      if (req.url === '/_status') return res.end(JSON.stringify({status: 'ok'}))
      if (this.verify_token && req.method === 'GET') return this._verify(req, res)
      if (req.method !== 'POST') return res.end()

      let body = ''

      req.on('data', (chunk) => {
        body += chunk
      })

      req.on('end', () => {
        // check message integrity
        if (this.app_secret) {
          let hmac = crypto.createHmac('sha1', this.app_secret)
          hmac.update(body)

          if (req.headers['x-hub-signature'] !== `sha1=${hmac.digest('hex')}`) {
            this.emit('error', new Error('Message integrity check failed'))
            return res.end(JSON.stringify({status: 'not ok', error: 'Message integrity check failed'}))
          }
        }

        let parsed = JSON.parse(body)
        this._handleMessage(parsed)

        res.end(JSON.stringify({status: 'ok'}))
      })
    }
  }

  _getQs (qs) {
    if (typeof qs === 'undefined') {
      qs = {}
    }

    if (this.debug) {
      qs['debug'] = this.debug
    }

    return qs
  }

  _handleMessage (json) {
    let entries = json.entry

    entries.forEach((entry) => {
      let events = entry.messaging

      events.forEach((event) => {
        event.page_id = entry.id;

        // handle inbound messages and echos
        if (event.message) {
          if (event.message.is_echo) {
            this._handleEvent('echo', event)
          } else {
            this._handleEvent('message', event)
          }
        }

        // handle postbacks
        if (event.postback) {
          this._handleEvent('postback', event)
        }

        // handle message delivered
        if (event.delivery) {
          this._handleEvent('delivery', event)
        }

        // handle message read
        if (event.read) {
          this._handleEvent('read', event)
        }

        // handle authentication
        if (event.optin) {
          this._handleEvent('authentication', event)
        }

        // handle account_linking
        if (event.account_linking && event.account_linking.status) {
          if (event.account_linking.status === 'linked') {
            this._handleEvent('accountLinked', event)
          } else if (event.account_linking.status === 'unlinked') {
            this._handleEvent('accountUnlinked', event)
          }
        }
      })
    })
  }

  _getActionsObject (event) {
    return {
      setTyping: (accessToken, typingState, cb) => {
        let senderTypingAction = typingState ? 'typing_on' : 'typing_off'
        this.sendSenderAction(event.sender.id, accessToken, senderTypingAction, cb)
      },
      markRead: (accessToken, cb) => {
        this.sendSenderAction(event.sender.id, accessToken, 'mark_seen', cb);
      }
    }
  }

  _verify (req, res) {
    let query = qs.parse(url.parse(req.url).query)

    if (query['hub.verify_token'] === this.verify_token) {
      return res.end(query['hub.challenge'])
    }

    return res.end('Error, wrong validation token')
  }

  _verifySignature(req, res, buf) {
    var signature = req.headers["x-hub-signature"];

    if (!signature) {

    } else {
      var elements = signature.split('=');
      var method = elements[0];
      var signatureHash = elements[1];

      var expectedHash = crypto.createHmac('sha1', this.app_secret)
      .update(buf)
      .digest('hex');

      if (signatureHash != expectedHash) {
        throw new Error("Couldn't validate the request signature.");
      }
    }
  }

  _handleEvent (type, event) {
    this.emit(type, event, this.sendMessage.bind(this, event.sender.id), this._getActionsObject(event))
  }
}

module.exports = Bot
