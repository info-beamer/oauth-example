'use strict';
// This code is based on 
// https://github.com/aaronpk/pkce-vanilla-js

(async () => {
const config = window.CONFIG

function parse_query_string(qs) {
  if (qs == "") { return {} }
  const segments = qs.split("&").map(s => s.split("="))
  let parsed = {}
  segments.forEach(s => parsed[s[0]] = decodeURIComponent(s[1]).replace(/\+/g, ' '))
  return parsed
}

function random() {
  const array = new Uint32Array(16)
  window.crypto.getRandomValues(array)
  return Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('')
}

function sha256(plain) {
  const encoder = new TextEncoder()
  const data = encoder.encode(plain)
  return window.crypto.subtle.digest('SHA-256', data)
}

// Base64-urlencodes the input string
function base64url_encode(str) {
  // Convert the ArrayBuffer to string using Uint8 array to conver to what btoa accepts.
  // btoa accepts chars only within ascii 0-255 and base64 encodes them.
  // Then convert the base64 encoded to base64url encoded
  //   (replace + with -, replace / with _, trim trailing =)
  return btoa(String.fromCharCode.apply(null, new Uint8Array(str)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function pkce_verifier_to_challenge(v) {
  const hashed = await sha256(v)
  return base64url_encode(hashed)
}

async function redirect_to_authorization(next_path) {
  localStorage.setItem("next_path", next_path || "/")

  const state = random()
  localStorage.setItem("pkce_state", state)

  // Create and store a new PKCE code_verifier (the plaintext random secret)
  const code_verifier = random()
  localStorage.setItem("pkce_code_verifier", code_verifier);

  // Hash and base64-urlencode the secret to use as the challenge
  const code_challenge = await pkce_verifier_to_challenge(code_verifier);

  // Build the authorization URL
  const url = config.authorization_endpoint 
      + "?response_type=code"
      + "&client_id="+encodeURIComponent(config.client_id)
      + "&state="+encodeURIComponent(state)
      + "&scope="+encodeURIComponent(config.requested_scopes)
      + "&redirect_uri="+encodeURIComponent(config.redirect_uri)
      + "&code_challenge="+encodeURIComponent(code_challenge)
      + "&code_challenge_method=S256"

  // Redirect to the authorization server
  window.location = url
}

async function handle_authorization_return() {
  const q = parse_query_string(window.location.search.substring(1))

  // If there's no oauth 'state' parameter, there's nothing to do.
  if (!q.state)
    return

  if (localStorage.getItem("pkce_state") != q.state) {
    // If the state doesn't match the locally saved state,
    // we have to abort the flow. Someone might have started
    // it without our knowledge.
    alert("Invalid state")
  } else if (q.error) {
    // If there's an error response, print it out
    alert(q.error_description)
  } else if (q.code) {
    // Exchange the authorization code for an access token
    const resp = await Vue.http.post(config.token_endpoint, {
      grant_type: "authorization_code",
      code: q.code,
      client_id: config.client_id,
      redirect_uri: config.redirect_uri,
      code_verifier: localStorage.getItem("pkce_code_verifier")
    })

    // Save retrieved access_token. The app can start init it with.
    localStorage.setItem('access_token', resp.data.access_token)

    // If there's a next_path, we instruct to router
    // to go there once its fully initialized.
    const next_path = localStorage.getItem("next_path")
    if (next_path) {
      router.push(next_path)
    }
  }

  // Clean these up since we don't need them anymore
  localStorage.removeItem("next_path")
  localStorage.removeItem("pkce_state")
  localStorage.removeItem("pkce_code_verifier")
  window.history.replaceState({}, null, config.app_root)
}

const store = new Vuex.Store({
  strict: true,
  state: {
    ready: false,
    access_token: null,
    info: null,
  },
  getters: {
    is_logged_in(state) {
      return !!state.access_token
    },
  },
  mutations: {
    init(state) {
      state.access_token = localStorage.getItem('access_token')
    },
    set_login(state, info) {
      state.info = info
    },
    wipe(state) {
      state.access_token = null
      state.info = null
      localStorage.removeItem('access_token')
    },
    ready(state) {
      state.ready = true
    },
  },
  actions: {
    async init({commit, state}) {
      commit('init')
      if (state.access_token) {
        // We have an access token? Fetch basic account
        // info. If that doesn't work, wipe the login state.
        try {
          let resp = await Vue.http.get('account')
          commit('set_login', resp.data)
        } catch (e) {
          commit('wipe')
        }
      }
      commit('ready')
    },
    async logout({commit}) {
      try {
        // kill the session. This invalidates the access_token
        // used to call this endpoint.
        await Vue.http.post('account/session/destroy')
      } catch (e) {
        // Ignore errors. Nothing do to here.
      }
      commit('wipe')
    },
  }
})

Vue.component('nav-bar', {
  template: `
    <div class='nav-bar' v-if='$store.state.ready'>
      <b>Example App</b> - 
      <router-link to='/'>Home</router-link>
      |
      <router-link to='/info'>Show account info</router-link>

      <div class='right' v-if='$store.getters.is_logged_in'>
        {{$store.state.info.email}}
        <button @click='logout'>logout</button>
      </div>
    </div>
  `,
  methods: {
    async logout() {
      router.push('/').catch(err => {})
      await this.$store.dispatch('logout')
    }
  }
})

const Index = Vue.component('index-view', {
  template: `
    <div>
      <p>
        This is an example of how a Vue based app might use the
        <a href='https://info-beamer.com/doc/oauth'>info-beamer OAuth authorization</a>.
        Clicking on the <em>Show account info</em>
        tab requests your authorization to access your account data.
        If the access if granted, you'll see basic account information.
      </p>
      <p>
        The full source code for this app is available on
        <a href='https://github.com/info-beamer/oauth-example'>github</a>.
      </p>
    </div>
  `,
})

const Info = Vue.component('info-view', {
  template: `
    <div>
      <p>
        Viewing account info of <b>{{$store.state.info.email}}</b>
      </p>
      <p>
        Balance: {{$store.state.info.balance}}
      </p>
      <p>
        Usage:
        {{$store.state.info.usage.devices}} device(s),
        {{$store.state.info.usage.storage}} bytes of storage.
      </p>
    </div>
  `,
})

Vue.component('oauth-example', {
  template: `
    <div>
      <nav-bar/>
      <router-view/>
    </div>
  `,
})

// All info-beamer endpoints expect x-www-form-urlencoded
Vue.http.options.emulateJSON = true

// Set up router first. That way the authorization return
// can push the target path on successful authorization.
const router = new VueRouter({
  base: config.app_root,
  routes: [
    {path: '/', component: Index, meta: { no_auth: true }},
    {path: '/info', component: Info },
  ]
})

// Check if there's any oauth authorization parameters in
// the current url and handle them.
await handle_authorization_return()

// Now set up the rest of the app
router.beforeEach(async (to, from, next) => {
  // Is the url needs authorization and we don't have an API key,
  // redirect to get one.
  if (!to.matched.some(record => record.meta.no_auth) && !store.getters.is_logged_in) {
    return redirect_to_authorization(to.path)
  }
  next()
})

// Configure vue-resource for the info-beamer API
Vue.http.options.root = window.CONFIG.api_root
Vue.http.interceptors.push(request => {
  const api_key = store.state.access_token
  request.headers.set('Authorization', 'Bearer ' + api_key)
  return response => {
    if (response.status == 401) {
      store.commit('wipe')
    }
  }
})

// Now start the app. This will check he access token
// and fetch basic account info if possible.
await store.dispatch('init')

// Render the app
new Vue({el: '#app', store, router})

})()
