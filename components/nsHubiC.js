/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

/* This file implements the nsIMsgCloudFileProvider interface.
 *
 * This component handles the OVH hubiC implementation of the
 * nsIMsgCloudFileProvider interface.
 */

 /*jshint moz:true */

const {classes: Cc, interfaces: Ci, utils: Cu, results: Cr} = Components;

Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource:///modules/http.jsm");
Cu.import("resource:///modules/gloda/log4moz.js");
Cu.import("resource:///modules/cloudFileAccounts.js");
Cu.import("resource://hubiC/OAuth2.jsm");

const kAuthRefreshToken = "hubiC refresh token";
const kAuthAccessTokenExpiration = "hubiC access token expiration";
const kAuthSwiftEndpoint = "hubiC Swift Endpoint";
const kAuthSwiftToken = "hubiC Swift token";
const kAuthSwiftExpiration = "hubic Swift token expiration";

const kMaxFileSize = 1073741824; // hubiC, max 10G
const kContainerPath = "/default";
var kFilesPutPath = "/thunderbird-attachements";
var kPublicationDelay = 30;

const kAppKey = "api_hubic_GBHc2IB1k44ujyqg32bYmfBOVo2CKrpN";
const kAppSecret = "UZtRzeDfFpyPVlY7Q0Mvnkbca0iBdDSuMARE6QdYOS2JhJKVohbx6i4pDMpRkOtY";
const kScope = "usage.r,account.r,credentials.r,links.wd";

const gServerUrl = "https://api.hubic.com/";
const gUsagePath = "1.0/account/usage";
const gSwiftTokenPath = "1.0/account/credentials";
const gSharedLink = "1.0/account/links";

function wwwFormUrlEncode(aStr) {
  return encodeURIComponent(aStr)
    .replace(/!/g, '%21')
    .replace(/'/g, '%27')
    .replace(/\(/g, '%28')
    .replace(/\)/g, '%29')
    .replace(/\*/g, '%2A');
}


function nsHubiC() {
  // this.log = Log4Moz.getConfiguredLogger("hubic", Log4Moz.Level.Info, Log4Moz.Level.Debug, Log4Moz.Level.Debug);
  this.log = Log4Moz.getConfiguredLogger("hubic");
}

nsHubiC.prototype = {

  /* nsISupports */
  QueryInterface: XPCOMUtils.generateQI([Ci.nsIMsgCloudFileProvider]),

  classID: Components.ID("{92E625EE-545D-11E2-A143-E9D96188709B}"),

  get type() "hubiC",
  get displayName() "hubiC by OVH",
  get serviceURL() "https://hubic.com",
  get iconClass() "chrome://hubiC/content/hubic-32.png",
  get accountKey() this._accountKey,
  get lastError() this._lastErrorText,
  get settingsURL() "chrome://hubiC/content/settings.xhtml",
  get managementURL() "chrome://hubiC/content/management.xhtml",

  _accountKey: false,
  _prefBranch: null,
  _userName: "",
  _password: "",
  _loggedIn: false,
  _userInfo: null,
  _file : null,
  _uploadingFile : null,
  _uploader : null,
  _lastErrorStatus : 0,
  _lastErrorText : "",
  _maxFileSize : kMaxFileSize,
  _totalStorage: -1,
  _fileSpaceUsed : -1,
  _uploads: [],
  _urlsForFiles : {},
  _uploadInfo : {}, // upload info keyed on aFiles.

  /**
   * Initialize this instance of nsHubiC, setting the accountKey.
   *
   * @param aAccountKey the account key to initialize this provider with
   */
  init: function nsHubiC_init(aAccountKey) {
    // Account
    this._accountKey = aAccountKey;
    this._prefBranch = Services.prefs.getBranch("mail.cloud_files.accounts." +
                                                aAccountKey + ".");
    this._loggedIn = this._cachedAccessToken !== "";

    // hubiC preferences
    this._prefBranch = Services.prefs.getBranch("extensions.hubic.");
    if (!this._prefBranch.prefHasUserValue("publicationDelay") ||
        this._prefBranch.getIntPref("publicationDelay") === 0) {
      this._prefBranch.setIntPref("publicationDelay", kPublicationDelay);
    }

    if (!this._prefBranch.prefHasUserValue("filesPutPath")) {
      this._prefBranch.setCharPref("filesPutPath", kFilesPutPath);
    }

    kPublicationDelay = this._prefBranch.getIntPref("publicationDelay");
    kFilesPutPath = this._prefBranch.getCharPref("filesPutPath");

    // OAuth2
    this._connection = new OAuth2(
      gServerUrl,
      kScope, kAppKey, kAppSecret
    );

    this._connection.authURI = gServerUrl + 'oauth/auth/';
    this._connection.tokenURI = gServerUrl + 'oauth/token/';
    this._connection.completionURI = 'https://addons.mozilla.org/';
  },

  /**
   * The callback passed to an nsHubiCFileUploader, which is fired when
   * nsHubiCFileUploader exits.
   *
   * @param aRequestObserver the request observer originally passed to
   *                         uploadFile for the file associated with the
   *                         nsHubiCFileUploader
   * @param aStatus the result of the upload
   */
  _uploaderCallback: function nsHubiC__uploaderCallback(aRequestObserver, aStatus) {
    aRequestObserver.onStopRequest(null, null, aStatus);
    this._uploadingFile = null;
    this._uploads.shift();
    if (this._uploads.length > 0) {
      let nextUpload = this._uploads[0];
      this.log.info("chaining upload, file = " + nextUpload.file.leafName);
      this._uploadingFile = nextUpload.file;
      this._uploader = nextUpload;
      try {
        this.uploadFile(nextUpload.file, nextUpload.callback);
      }
      catch (ex) {
        nextUpload.callback(nextUpload.requestObserver, Cr.NS_ERROR_FAILURE);
      }
    }
    else {
      this._uploader = null;
    }
  },

  /** 
   * Attempts to upload a file to hubiC.
   *
   * @param aFile the nsILocalFile to be uploaded
   * @param aCallback an nsIRequestObserver for listening for the starting
   *                  and ending states of the upload.
   */
  uploadFile: function nsHubiC_uploadFile(aFile, aCallback) {
    if (Services.io.offline)
      throw Ci.nsIMsgCloudFileProvider.offlineErr;

    this.log.info("uploading " + aFile.leafName);

    var processUploadFile = function () {
      // Some ugliness here - we stash requestObserver here, because we might
      // use it again in _getUserInfo.
      this.requestObserver = aCallback;

      // if we're uploading a file, queue this request.
      if (this._uploadingFile && this._uploadingFile != aFile) {
        let uploader = new nsHubiCFileUploader(this, aFile,
                                               this._uploaderCallback.bind(this),
                                               aCallback);
        this._uploads.push(uploader);
        return;
      }
      this._file = aFile;
      this._uploadingFile = aFile;

      let successCallback = this._finishUpload.bind(this, aFile, aCallback);
      if (!this._loggedIn)
        return this._logonAndGetUserInfo(successCallback, null, true);
      if (!this._userInfo)
        return this._getUserInfo(successCallback);
      successCallback();
    }.bind(this);

    this._getSwiftToken(processUploadFile, aCallback);
  },

  /**
   * A private function used to ensure that we can actually upload the file
   * (we haven't exceeded file size or quota limitations), and then attempts
   * to kick-off the upload.
   *
   * @param aFile the nsILocalFile to upload
   * @param aCallback an nsIRequestObserver for monitoring the starting and
   *                  ending states of the upload.
   */
  _finishUpload: function nsHubiC_finishUpload(aFile, aCallback) {
    let exceedsFileLimit = Ci.nsIMsgCloudFileProvider.uploadExceedsFileLimit;
    let exceedsQuota = Ci.nsIMsgCloudFileProvider.uploadWouldExceedQuota;
    if (aFile.fileSize > this._maxFileSize)
      return aCallback.onStopRequest(null, null, exceedsFileLimit);
    if (aFile.fileSize > this.remainingFileSpace)
      return aCallback.onStopRequest(null, null, exceedsQuota);

    delete this._userInfo; // force us to update userInfo on every upload.

    if (!this._uploader) {
      this._uploader = new nsHubiCFileUploader(this, aFile,
                                                 this._uploaderCallback
                                                     .bind(this),
                                                 aCallback);
      this._uploads.unshift(this._uploader);
    }

    this._uploadingFile = aFile;
    this._uploader.uploadFile();
  },

  /**
   * Attempts to cancel a file upload.
   *
   * @param aFile the nsILocalFile to cancel the upload for.
   */
  cancelFileUpload: function nsHubiC_cancelFileUpload(aFile) {
    if (this._uploadingFile.equals(aFile)) {
      this._uploader.cancel();
    }
    else {
      for (let i = 0; i < this._uploads.length; i++)
        if (this._uploads[i].file.equals(aFile)) {
          this._uploads[i].requestObserver.onStopRequest(
            null, null, Ci.nsIMsgCloudFileProvider.uploadCanceled);
          this._uploads.splice(i, 1);
          return;
        }
    }
  },

  _apiRequest: function nsHubiC_apiRequest(url, params, successCallback, failureCallback, method) {
    var doApiRequest = function () {
      let headers = [
        ["Authorization", "Bearer " + this._cachedAccessToken],
        ["Accept", "application/json"]
      ];

      this.log.info('API Request: ', url, JSON.stringify(headers), JSON.stringify(params));
      doXHRequest(
        url, headers, params,
        successCallback,
        function (err, aResponseText) {
          let aResponse = JSON.parse(aResponseText);
          if (aResponse.error === 'invalid_token') {
            this._cachedAccessToken = null;
            this._cachedAccessTokenExpiration = 0;
            this._cachedRefreshToken = null;
            this._apiRequest(url, params, successCallback, failureCallback, method);
          }
          else {
            failureCallback(err, aResponseText);
          }
        }.bind(this),
        this, method
      );
    }.bind(this);

    var refreshCb = function () {
      this._loggedIn = true;
      this._cachedAccessToken = this._connection.accessToken;
      this._cachedAccessTokenExpiration = this._connection.tokenExpires;
      this._cachedRefreshToken = this._connection.refreshToken;
      doApiRequest();
    }.bind(this);

    // No tokens
    if (!this._cachedRefreshToken || this._cachedRefreshToken.length === 0) {
      return this._connection.connect(refreshCb, failureCallback, true);
    }

    // Refresh
    if (this._cachedAccessTokenExpiration < new Date().getTime()) {
      this._connection.refreshToken = this._cachedRefreshToken;
      this._connection.connect(refreshCb, failureCallback, false, true);
    }
    else {
      doApiRequest();
    }
  },

  /**
   * A private function used to retrieve the profile information for the
   * user account associated with the accountKey.
   *
   * @param successCallback the function called if information retrieval
   *                        is successful
   * @param failureCallback the function called if information retrieval fails
   */
   _getUserInfo: function nsHubic_getUserInfo(successCallback, failureCallback) {
    if (!successCallback)
      successCallback = function() {
        this.requestObserver
            .onStopRequest(null, null,
                           this._loggedIn ? Cr.NS_OK : Ci.nsIMsgCloudFileProvider.authErr);
      }.bind(this);

    if (!failureCallback)
      failureCallback = function () {
        this.requestObserver
            .onStopRequest(null, null, Ci.nsIMsgCloudFileProvider.authErr);
      }.bind(this);

    this._apiRequest(
      gServerUrl + gUsagePath, null,
      function (aResponseText) {
        this._userInfo = JSON.parse(aResponseText);
        this._totalStorage = this._userInfo.quota;
        this._fileSpaceUsed = this._userInfo.used;
        successCallback();
      }.bind(this),
      failureCallback
    );
  },

  _getSwiftToken: function nsHubiC_getSwiftToken(successCallback, failureCallback) {
    if (this._cachedSwiftExpiration < new Date().getTime()) {
      this._apiRequest(
        gServerUrl + gSwiftTokenPath, null,
        function (aResponseText) {
          this.log.info(aResponseText);
          let swift = JSON.parse(aResponseText);
          this._cachedSwiftExpiration = new Date(swift.expires);
          this._cachedSwiftToken = swift.token;
          this._cachedSwiftEndpoint = swift.endpoint;
          successCallback();
        }.bind(this),
        failureCallback
      );
    }
    else {
      successCallback();
    }
  },

  _createLink: function nsHubiC_createLink(uri, successCallback, failureCallback) {
    this._apiRequest(
      gServerUrl + gSharedLink,
      [
        ['comment', 'Thunderbird Filelink - ' + new Date()],
        ['container', 'default'],
        ['mode', 'ro'],
        ['type', 'file'],
        ['uri', uri],
        ['ttl', kPublicationDelay],
      ],
      function (aResponseText) {
        this.log.info(aResponseText);
        successCallback(JSON.parse(aResponseText));
      }.bind(this),
      failureCallback
    );
  },

  _deleteLink: function nsHubiC_deleteLink(uri, successCallback, failureCallback) {
    this._apiRequest(
      gServerUrl + gSharedLink,
      [['uri', uri]],
      function (aResponseText) {
        this.log.info(aResponseText);
        successCallback(JSON.parse(aResponseText));
      }.bind(this),
      failureCallback,
      'DELETE'
    );
  },

  /**
   * A private function that first ensures that the user is logged in, and then
   * retrieves the user's profile information.
   *
   * @param aSuccessCallback the function called on successful information
   *                         retrieval
   * @param aFailureCallback the function called on failed information retrieval
   * @param aWithUI a boolean for whether or not we should display authorization
   *                UI if we don't have a valid token anymore, or just fail out.
   */
  _logonAndGetUserInfo: function nsHubiC_logonAndGetUserInfo(aSuccessCallback,
                                                             aFailureCallback,
                                                             aWithUI) {
    if (!aFailureCallback)
      aFailureCallback = function () {
        this.requestObserver
            .onStopRequest(null, null, Ci.nsIMsgCloudFileProvider.authErr);
      }.bind(this);

    return this.logon(function() {
      this._getUserInfo(aSuccessCallback, aFailureCallback);
    }.bind(this), aFailureCallback, aWithUI);
  },

  /**
   * For some nsILocalFile, return the associated sharing URL.
   *
   * @param aFile the nsILocalFile to retrieve the URL for
   */
  urlForFile: function nsHubiC_urlForFile(aFile) {
    return this._urlsForFiles[aFile.path];
  },

  /**
   * Updates the profile information for the account associated with the
   * account key.
   *
   * @param aWithUI a boolean for whether or not we should display authorization
   *                UI if we don't have a valid token anymore, or just fail out.
   * @param aCallback an nsIRequestObserver for observing the starting and
   *                  ending states of the request.
   */
  refreshUserInfo: function nsHubiC_refreshUserInfo(aWithUI, aCallback) {
    if (Services.io.offline)
      throw Ci.nsIMsgCloudFileProvider.offlineErr;
    this.requestObserver = aCallback;
    aCallback.onStartRequest(null, null);
    if (!this._loggedIn)
      return this._logonAndGetUserInfo(null, null, aWithUI);
    if (!this._userInfo)
      return this._getUserInfo();
    return this._userInfo;
  },


  /**
   * Our hubiC implementation does not implement the createNewAccount
   * function defined in nsIMsgCloudFileProvider.idl.
   */
  createNewAccount: function nsHubiC_createNewAccount(aEmailAddress,
                                                      aPassword, aFirstName,
                                                      aLastName) {
    return Cr.NS_ERROR_NOT_IMPLEMENTED;
  },

  /**
   * If the user already has an account, we can get the user to just login
   * to it via OAuth.
   *
   * This function does not appear to be called from the BigFiles UI, and
   * might be excisable.
   */
  createExistingAccount: function nsHubiC_createExistingAccount(aRequestObserver) {
    let successCb = function(aResponseText, aRequest) {
      aRequestObserver.onStopRequest(null, this, Cr.NS_OK);
    }.bind(this);

    let failureCb = function(aResponseText, aRequest) {
      aRequestObserver.onStopRequest(null, this,
                                     Ci.nsIMsgCloudFileProvider.authErr);
    }.bind(this);

    this.logon(successCb, failureCb, true);
  },

  /**
   * If the provider doesn't have an API for creating an account, perhaps
   * there's a url we can load in a content tab that will allow the user
   * to create an account.
   */
  get createNewAccountUrl() "",

  /**
   * For a particular error, return a URL if Dropbox has a page for handling
   * that particular error.
   *
   * @param aError the error to get the URL for
   */
  providerUrlForError: function nsHubiC_providerUrlForError(aError) {
    return "";
  },

  /**
   * If we don't know the limit, this will return -1.
   */
  get fileUploadSizeLimit() this._maxFileSize,
  get remainingFileSpace() this._totalStorage - this._fileSpaceUsed,
  get fileSpaceUsed() this._fileSpaceUsed,

  /**
   * Attempt to delete an upload file if we've uploaded it.
   *
   * @param aFile the file that was originall uploaded
   * @param aCallback an nsIRequestObserver for monitoring the starting and
   *                  ending states of the deletion request.
   */
  deleteFile: function nsHubiC_deleteFile(aFile, aCallback) {
    if (Services.io.offline)
      throw Ci.nsIMsgCloudFileProvider.offlineErr;

    let fileHubic = this._uploadInfo[aFile.path];
    if (!fileHubic)
      throw Cr.NS_ERROR_FAILURE;

    this.requestObserver = aCallback;

    let url = this._cachedSwiftEndpoint + kContainerPath + fileHubic;
    let headers = [["X-Auth-Token", this._cachedSwiftToken]];

    this.request = doXHRequest(url, headers, null,
      function(aResponseText, aRequest) {
        this.request = null;
        this.log.info("success deleting file " + aResponseText);

        var deleteLink = function () {
          aCallback.onStopRequest(null, null, Cr.NS_OK);
        };

        this._deleteLink(fileHubic, deleteLink, deleteLink);
      }.bind(this),
      function(aException, aResponseText, aRequest) {
        this.request = null;
        this.log.info("failed deleting file response = " + aResponseText);
        aCallback.onStopRequest(null, null, Ci.nsIMsgCloudFileProvider.uploadErr);
      }.bind(this), this, "DELETE"
    );
  },

  /**
   * logon to the hubiC account.
   *
   * @param successCallback - called if logon is successful
   * @param failureCallback - called back on error.
   * @param aWithUI if false, logon fails if it would have needed to put up UI.
   *                This is used for things like displaying account settings,
   *                where we don't want to pop up the oauth ui.
   */
  logon: function nsHubiC_logon(successCallback, failureCallback, aWithUI) {
    let accessToken = this._cachedAccessToken;
    let refreshToken = this._cachedRefreshToken;

    if (!aWithUI && (!accessToken.length || !refreshToken.length)) {
      failureCallback();
      return;
    }

    this._connection.connect(
      function () {
        this.log.info("success connecting");
        this._loggedIn = true;
        this._cachedAccessToken = this._connection.accessToken;
        this._cachedAccessTokenExpiration = this._connection.tokenExpires;
        this._cachedRefreshToken = this._connection.refreshToken;
        successCallback();
      }.bind(this),
      function () {
        this.log.error("failed connecting");
        failureCallback();
      }.bind(this),
      true
    );
  },

  get _cachedAccessToken() {
    let accessToken = cloudFileAccounts.getSecretValue(
      this.accountKey, 
      cloudFileAccounts.kTokenRealm
    );

    if (!accessToken) {
      return "";
    }

    return accessToken;
  },

  set _cachedAccessToken(aAccessToken) {
    cloudFileAccounts.setSecretValue(
      this.accountKey,
      cloudFileAccounts.kTokenRealm,
      aAccessToken
    );
  },

  get _cachedAccessTokenExpiration() {
    let aAccessTokenExpiration = cloudFileAccounts.getSecretValue(
      this.accountKey,
      kAuthAccessTokenExpiration
    );

    if (!aAccessTokenExpiration) {
      return 0;
    }

    return aAccessTokenExpiration;
  },

  set _cachedAccessTokenExpiration(aAccessTokenExpiration) {
    cloudFileAccounts.setSecretValue(
      this.accountKey,
      kAuthAccessTokenExpiration,
      aAccessTokenExpiration
    );
  },

  get _cachedRefreshToken() {
    let refreshToken = cloudFileAccounts.getSecretValue(
      this.accountKey,
      kAuthRefreshToken
    );

    return refreshToken;
  },

  set _cachedRefreshToken(aRefreshToken) {
    cloudFileAccounts.setSecretValue(
      this.accountKey,
      kAuthRefreshToken,
      aRefreshToken
    );
  },

  get _cachedSwiftEndpoint() {
    let endpoint = cloudFileAccounts.getSecretValue(
      this.accountKey,
      kAuthSwiftEndpoint
    );

    return endpoint;
  },

  set _cachedSwiftEndpoint(endpoint) {
    cloudFileAccounts.setSecretValue(
      this.accountKey,
      kAuthSwiftEndpoint,
      endpoint
    );
  },

  get _cachedSwiftToken() {
    let token = cloudFileAccounts.getSecretValue(
      this.accountKey,
      kAuthSwiftToken
    );

    return token;
  },

  set _cachedSwiftToken(token) {
    cloudFileAccounts.setSecretValue(
      this.accountKey,
      kAuthSwiftToken,
      token
    );
  },

  get _cachedSwiftExpiration() {
    let expiration = cloudFileAccounts.getSecretValue(
      this.accountKey,
      kAuthSwiftExpiration
    );

    if (!expiration) {
      return 0;
    }

    return expiration;
  },

  set _cachedSwiftExpiration(expiration) {
    cloudFileAccounts.setSecretValue(
      this.accountKey,
      kAuthSwiftExpiration,
      expiration
    );
  },
};

function nsHubiCFileUploader(aHubic, aFile, aCallback, aRequestObserver) {
  this.hubic = aHubic;
  this.log = this.hubic.log;
  this.file = aFile;
  this.callback = aCallback;
  this.requestObserver = aRequestObserver;
}

nsHubiCFileUploader.prototype = {
  file : null,
  callback : null,
  request : null,

  /**
   * Kicks off the upload request for the file associated with this Uploader.
   */
  uploadFile: function nsDFU_uploadFile() {
    this.requestObserver.onStartRequest(null, null);
    this.createDirectory(kFilesPutPath, function (created) {
      if (!created) {
        return this.callback(this.requestObserver,
                             Ci.nsIMsgCloudFileProvider.uploadErr);
      }

      this.log.info("ready to upload file " + wwwFormUrlEncode(this.file.leafName));
      let fileHubic = kFilesPutPath + '/' + wwwFormUrlEncode(new Date().getTime() + '-' + this.file.leafName);
      let url = this.hubic._cachedSwiftEndpoint + kContainerPath + fileHubic;
      
      let fileContents = "";
      let fstream = Cc["@mozilla.org/network/file-input-stream;1"]
                       .createInstance(Ci.nsIFileInputStream);
      fstream.init(this.file, -1, 0, 0);
      let bufStream = Cc["@mozilla.org/network/buffered-input-stream;1"].
        createInstance(Ci.nsIBufferedInputStream);
      bufStream.init(fstream, this.file.fileSize);
      bufStream = bufStream.QueryInterface(Ci.nsIInputStream);

      let mimeType = "text/plain";
      try {
        let mimeService = Components.classes["@mozilla.org/mime;1"]
                .getService(Components.interfaces.nsIMIMEService);
        mimeType = mimeService.getTypeFromFile(this.file);
      }
      catch(e) { /* just use text/plain */ }

      let headers = [["Content-Length", fstream.available()],
                     ["Content-Type", mimeType],
                     ["X-Auth-Token", this.hubic._cachedSwiftToken]];

      this.request = doXHRequest(url, headers, bufStream,
        function(aResponseText, aRequest) {
          this.request = null;
          this.log.info("Success putting file " + aResponseText);
          this.hubic._uploadInfo[this.file.path] = fileHubic;
          this._getShareUrl.call(this.hubic, this.file, fileHubic,
                                 this.callback, this.requestObserver);
        }.bind(this),
        function(aException, aResponseText, aRequest) {
          this.request = null;
          this.log.info("Failed putting file response = " +
                        aRequest.status + " / " + aResponseText + " / " + aException);
          if (this.callback) {
            this.callback(this.requestObserver,
                          Ci.nsIMsgCloudFileProvider.uploadErr);
          }
        }.bind(this), this, "PUT"
      );
    }.bind(this));
  },

  /**
   * Create upload directory if not exists
   * It don't use doXHRequest to be able to overrideMimeType without charset
   */
  createDirectory: function nsDFU_createDirectory(dir, callback) {
    this.log.info('createDirectory', dir);
    var aDir = dir.split('/'), remaining = 0, result = true;

    var createDirectoryProcess = function(dir, exists) {
      if (!exists) {
        let xhr = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"]
                    .createInstance(Ci.nsIXMLHttpRequest);
        xhr.mozBackgroundRequest = true;
        xhr.open("PUT", this.hubic._cachedSwiftEndpoint + kContainerPath + dir);
        xhr.setRequestHeader("Content-Length", 0);
        this.log.info("X-Auth-Token: " + this.hubic._cachedSwiftToken);
        xhr.setRequestHeader("X-Auth-Token", this.hubic._cachedSwiftToken);
        xhr.setRequestHeader("Content-Type", "application/directory");
        xhr.overrideMimeType("application/directory");

        xhr.onerror = function(aRequest) {
          this.log.error("Fail to create upload directory: " +
                         aRequest.target.status + " / " + aRequest.target.statusText);
          result = false;
        }.bind(this);

        xhr.onload = function(aRequest) {
          if (aRequest.target.status < 200 || aRequest.target.status >= 300) {
            xhr.onerror(aRequest);
          }
          else {
            this.log.info("Directory created: " + dir);
          }

          if (--remaining === 0) {
            callback(result);
          }
        }.bind(this);

        xhr.send();
      }
      else if (--remaining === 0) {
        callback(result);
      }
    };

    for (let i = 0; i < aDir.length ; i++) {
      if (aDir[i].length !== 0) {
        remaining++;
      }
    }

    dir = '';
    for (let i = 0; i < aDir.length ; i++) {
      if (aDir[i].length === 0) {
        continue;
      }

      kFilesPutPath = dir += '/' + aDir[i];
      if (i === aDir.length - 1) {
        this.hubic._prefBranch.setCharPref("filesPutPath", kFilesPutPath);
      }
      this.directoryExists(dir, createDirectoryProcess.bind(this));
    }
  },

  /**
   * Check if upload directory exists
   */
  directoryExists: function nsDFU_directoryExists(dir, callback) {
    let headers = [["X-Auth-Token", this.hubic._cachedSwiftToken]];
    let url = this.hubic._cachedSwiftEndpoint + kContainerPath + dir;
    this.request = doXHRequest(url, headers, null,
      function(aResponseText, aRequest) {
        this.request = null;
        this.log.debug("Upload directory exists: " + dir);
        callback(dir, true);
      }.bind(this),
      function(aException, aResponseText, aRequest) {
        this.request = null;
        this.log.debug("Upload directory don't exists: " + dir);
        callback(dir, false);
      }.bind(this), this, "HEAD"
    );
  },

  /**
   * Cancels the upload request for the file associated with this Uploader.
   */
  cancel: function nsDFU_cancel() {
    this.callback(this.requestObserver, Ci.nsIMsgCloudFileProvider.uploadCanceled);
    if (this.request) {
      let req = this.request;
      if (req.channel) {
        this.log.info("canceling channel upload");
        delete this.callback;
        req.channel.cancel(Cr.NS_BINDING_ABORTED);
      }
      this.request = null;
    }
  },

  /**
   * Private function that attempts to retrieve the sharing URL for the file
   * uploaded with this Uploader.
   *
   * @param aFile ...
   * @param url       the swift object file name
   * @param aCallback an nsIRequestObserver for monitoring the starting and
   *                  ending states of the URL retrieval request.
   */
  _getShareUrl: function nsDFU_getShareUrl(aFile, file, aCallback, aRequestObserver) {
    this.file = aFile;

    this._createLink(
      file,
      function (answer) {
        this._urlsForFiles[this.file.path] = answer.indirectUrl;
        aCallback(aRequestObserver, Cr.NS_OK);
      }.bind(this),
      function() {
        aCallback(aRequestObserver, Cr.NS_ERROR_FAILURE);
      }
    );
  },
};

const NSGetFactory = XPCOMUtils.generateNSGetFactory([nsHubiC]);