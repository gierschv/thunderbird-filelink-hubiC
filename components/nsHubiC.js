/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

/* This file implements the nsIMsgCloudFileProvider interface.
 *
 * This component handles the OVH hubiC implementation of the
 * nsIMsgCloudFileProvider interface.
 */

const {classes: Cc, interfaces: Ci, utils: Cu, results: Cr} = Components;

Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource:///modules/http.jsm");
Cu.import("resource:///modules/gloda/log4moz.js");
Cu.import("resource:///modules/cloudFileAccounts.js");

const kHubicStorageUrl = "hubiC storage URL";
const kHubicStorageToken = "hubiC storage token";
const kHubicNicHandle = "Nic Handler OVH";
const kHubicId = "hubic service identifier";

const kMaxFileSize = 1073741824; // hubiC, max 10G
const kContainerPath = "/default"
var kFilesPutPath = "/thunderbird-attachements";
var kPublicationDelay = 30;

const gWsUrl = "https://ws.ovh.com/";
const gWsLogin = "sessionHandler/r4/ws.dispatcher";
const gWsHubic = "hubic/r5/ws.dispatcher";

function wwwFormUrlEncode(aStr) {
  return encodeURIComponent(aStr).replace(/!/g, '%21')
                                 .replace(/'/g, '%27')
                                 .replace(/\(/g, '%28')
                                 .replace(/\)/g, '%29')
                                 .replace(/\*/g, '%2A');
}


function nsHubiC() {
  this.log = Log4Moz.getConfiguredLogger("hubic", Log4Moz.Level.Info, Log4Moz.Level.Debug, Log4Moz.Level.Debug);
}

nsHubiC.prototype = {
  /* nsISupports */
  QueryInterface: XPCOMUtils.generateQI([Ci.nsIMsgCloudFileProvider]),

  classID: Components.ID("{92E625EE-545D-11E2-A143-E9D96188709B}"),

  get type() "hubiC",
  get displayName() "hubiC by OVH",
  get serviceURL() "https://www.ovh.fr/hubiC",
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
    this._userName = this._prefBranch.getCharPref("username");
    this._loggedIn = this._cachedAuthToken != "";

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
  },

  /**
   * Returns the saved password for this account if one exists, or prompts
   * the user for a password. Returns the empty string on failure.
   *
   * @param aUsername the username associated with the account / password.
   * @param aNoPrompt a boolean for whether or not we should suppress
   *                  the password prompt if no password exists.  If so,
   *                  returns the empty string if no password exists.
   */
  getPassword: function nsHubiC_getPassword(aUsername, aNoPrompt) {
    this.log.info("Getting password for user: " + aUsername);

    if (aNoPrompt)
      this.log.info("Suppressing password prompt");

    let passwordURI = gWsUrl;
    let logins = Services.logins.findLogins({}, passwordURI, null, passwordURI);
    for each (let loginInfo in logins) {
      if (loginInfo.username == aUsername)
        return loginInfo.password;
    }
    if (aNoPrompt)
      return "";

    // OK, let's prompt for it.
    let win = Services.wm.getMostRecentWindow(null);

    let authPrompter = Services.ww.getNewAuthPrompter(win);
    let password = { value: "" };

    // Use the service name in the prompt text
    let serverUrl = gWsUrl;
    let userPos = gWsUrl.indexOf("//") + 2;
    let userNamePart = encodeURIComponent(this._userName) + '@';
    serverUrl = gWsUrl.substr(0, userPos) + userNamePart + gWsUrl.substr(userPos);
    let messengerBundle = Services.strings.createBundle(
      "chrome://messenger/locale/messenger.properties");
    let promptString = messengerBundle.formatStringFromName("passwordPrompt",
                                                            [this._userName,
                                                             this.displayName],
                                                            2);

    if (authPrompter.promptPassword(this.displayName, promptString, serverUrl,
                                    authPrompter.SAVE_PASSWORD_PERMANENTLY,
                                    password))
      return password.value;

    return "";
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
  _uploaderCallback : function nsHubiC__uploaderCallback(aRequestObserver, aStatus) {
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
    else
      this._uploader = null;
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
    this.log.info("getting user info");
    if (!this._userInfo)
      return this._getUserInfo(successCallback);
    successCallback();
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

  /**
   * A private function used to retrieve the profile information for the
   * user account associated with the accountKey.
   *
   * @param successCallback the function called if information retrieval
   *                        is successful
   * @param failureCallback the function called if information retrieval fails
   */
  _getUserInfo: function nsHubiC_getUserInfo(successCallback, failureCallback) {
    if (!successCallback) {
      successCallback = function() {
        this.requestObserver
            .onStopRequest(null, null,
                           this._loggedIn ? Cr.NS_OK : Ci.nsIMsgCloudFileProvider.authErr);
      }.bind(this);
    }

    if (!failureCallback) {
      failureCallback = function () {
        this.requestObserver
            .onStopRequest(null, null, Ci.nsIMsgCloudFileProvider.authErr);
      }.bind(this);
    }

    // Password
    if (this._password == undefined || !this._password) {
      this._password = this.getPassword(this._userName, false);

      if (this._password == "") {
        this.log.info("No password");
        return failureCallback();
      }
    }

    // WS
    this._wsLogin(this._cachedNic, this._password,
      function(answer) {
        this.log.debug("login: " + JSON.stringify(answer));
        this._wsGetHubic(answer.session.id, this._cachedHubicId,
          function(answer) {
            this.log.debug("getHubic: " + JSON.stringify(answer));
            this._totalStorage = answer.quota;
            this._fileSpaceUsed = answer.used;
            this._cachedStorageToken = answer.credentials.secret;
            this._cachedStorageUrl = atob(answer.credentials.username);
            successCallback();
          }.bind(this), failureCallback);
      }.bind(this), failureCallback);
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
     // XXX: replace this with a better function
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

    let url = this._cachedStorageUrl + kContainerPath + fileHubic;
    let headers = [["X-Auth-Token", this._cachedStorageToken]];

    this.request = doXHRequest(url, headers, null,
      function(aResponseText, aRequest) {
        this.request = null;
        this.log.info("success deleting file " + aResponseText);
        aCallback.onStopRequest(null, null, Cr.NS_OK);
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
    // Get Password from UI
    this.log.info("Logging in, aWithUI = " + aWithUI);
    if (this._password == undefined || !this._password) {
      this._password = this.getPassword(this._userName, !aWithUI);

      if (this._password == "") {
        this.log.info("No password");
        return failureCallback();
      }
    }

    // WS
    let _wsAnonymousSessionSuccess, _wsGetHubicsSuccess, _wsLoginSuccess, _wsGetHubicSuccess;

    _wsAnonymousSessionSuccess = function(answer) {
      this.log.info("Anonymous session: " + JSON.stringify(answer));
      this._wsGetHubics(answer.session.id, _wsGetHubicsSuccess.bind(this), failureCallback);
    };

    _wsGetHubicsSuccess = function(answer) {
      this.log.info("getHubics: " + JSON.stringify(answer));
      if (answer.length === 0) {
        this.log.error("getHubics: No hubiC for email " + this._userName);
        failureCallback();
      }
      else {
        this._cachedNic = answer[0].nic;
        this._cachedHubicId = answer[0].id;
        this.log.info("getHubics: " + this._cachedNic + " / " + this._cachedHubicId);
        this._wsLogin(this._cachedNic, this._password, _wsLoginSuccess.bind(this), failureCallback);
      }
    };

    _wsLoginSuccess = function(answer) {
      this.log.info("login: " + JSON.stringify(answer));
      this._wsGetHubic(answer.session.id, this._cachedHubicId,
                       _wsGetHubicSuccess.bind(this), failureCallback);
    };

    _wsGetHubicSuccess = function(answer) {
      this._totalStorage = answer.quota;
      this._fileSpaceUsed = answer.used;
      this._cachedStorageToken = answer.credentials.secret;
      this._cachedStorageUrl = atob(answer.credentials.username);
      successCallback();
    };

    this._wsAnonymousSession(_wsAnonymousSessionSuccess.bind(this), failureCallback);
  },

  _wsRequest: function nsHubic_wsRequest(url, params, successCallback, failureCallback) {
    this.log.info("Sending WS request to: " + url);
    let callUrl = url + "?params=" + wwwFormUrlEncode(JSON.stringify(params));
    let request = doXHRequest(callUrl, null, null,
      function(aResponseText) {
        let response = JSON.parse(aResponseText);
        if (response.error) {
          this.log.error("WS Error:" + response.error.message);
          if (failureCallback !== undefined) {
            return failureCallback(response.error.message);
          }
        }
        else {
          this.log.info("WS success on request to: " + url);
          if (successCallback !== undefined) {
            return successCallback(response.answer);
          }
        }
      }.bind(this),
      failureCallback, this, "GET"
    );
  },

  /**
   * ws : sessionHandler/getAnonymousSession
   */
  _wsAnonymousSession: function nsHubic_wsSessionHandlerAnonymousSession(successCallback, failureCallback) {
    return this._wsRequest(gWsUrl + gWsLogin + "/getAnonymousSession", {},
                           successCallback, failureCallback);
  },

  /**
   * ws : sessionHandler/login
   */
  _wsLogin: function nsHubic_wsSessionHandlerLogin(login, password, successCallback, failureCallback) {
    return this._wsRequest(gWsUrl + gWsLogin + "/login",
                           { login: login, password: password, context: "hubic" },
                           successCallback, failureCallback);
  },

  /**
   * ws : hubic/getHubics
   */
  _wsGetHubics: function nsHubic_wsHubicGetHubics(sessionId, successCallback, failureCallback) {
    return this._wsRequest(gWsUrl + gWsHubic + "/getHubics",
                           { sessionId: sessionId, email: this._userName },
                           successCallback, failureCallback);
  },

  /**
   * ws : hubic/getHubic
   */
  _wsGetHubic: function nsHubic_wsHubicGetHubic(sessionId, hubicId, successCallback, failureCallback) {
    return this._wsRequest(gWsUrl + gWsHubic + "/getHubic",
                           { sessionId: sessionId, hubicId: hubicId },
                           successCallback, failureCallback);
  },

  /**
   * ws : hubic/newPublication
   */
  _wsNewPublication: function nsHubic_wsHubicNewPublication(sessionId, hubicId, fileResource, successCallback, failureCallback) {
    return this._wsRequest(gWsUrl + gWsHubic + "/newPublication",
                           { sessionId: sessionId, hubicId: hubicId, fileResource: fileResource,
                             publicationParameters: { fileResourceType: "file", delay: kPublicationDelay }, containerName: "default" },
                           successCallback, failureCallback);
  },


  /**
   * Retrieves the cached storage URL for this account.
   */
  get _cachedStorageUrl() {
    let url = cloudFileAccounts.getSecretValue(this.accountKey, cloudFileAccounts.kTokenRealm);
    return url || "";
  },

  /**
   * Sets the cached storage URL for this account.
   *
   * @param aAuthToken the auth token to cache.
   */
  set _cachedStorageUrl(url) {
    cloudFileAccounts.setSecretValue(this.accountKey, cloudFileAccounts.kTokenRealm, url);
  },

  /**
   * Retrieves the cached storage token for this account.
   */
  get _cachedStorageToken() {
    let token = cloudFileAccounts.getSecretValue(this.accountKey, kHubicStorageToken);
    return token || "";
  },

  /**
   * Sets the cached storage token for this account.
   *
   * @param aAuthSecret the auth secret to cache.
   */
  set _cachedStorageToken(token) {
    cloudFileAccounts.setSecretValue(this.accountKey, kHubicStorageToken, token);
  },

  /**
   * Retrieves the cached storage token for this account.
   */
  get _cachedNic() {
    let nic = cloudFileAccounts.getSecretValue(this.accountKey, kHubicNicHandle);
    return nic || "";
  },

  /**
   * Sets the cached storage token for this account.
   *
   * @param aAuthSecret the auth secret to cache.
   */
  set _cachedNic(nic) {
    cloudFileAccounts.setSecretValue(this.accountKey, kHubicNicHandle, nic);
  },

  /**
   * Retrieves the cached storage token for this account.
   */
  get _cachedHubicId() {
    let id = cloudFileAccounts.getSecretValue(this.accountKey, kHubicId);
    return id || "";
  },

  /**
   * Sets the cached storage token for this account.
   *
   * @param aAuthSecret the auth secret to cache.
   */
  set _cachedHubicId(id) {
    cloudFileAccounts.setSecretValue(this.accountKey, kHubicId, id);
  }
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
      let url = this.hubic._cachedStorageUrl + kContainerPath + fileHubic;
      
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
                     ["X-Auth-Token", this.hubic._cachedStorageToken]];

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
    var aDir = dir.split('/'), remaining = 0, result = true;

    var createDirectoryProcess = function(dir, exists) {
      if (!exists) {
        let xhr = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"]
                    .createInstance(Ci.nsIXMLHttpRequest);
        xhr.mozBackgroundRequest = true;
        xhr.open("PUT", this.hubic._cachedStorageUrl + kContainerPath + dir);
        xhr.setRequestHeader("Content-Length", 0);
        this.log.info("X-Auth-Token: " + this.hubic._cachedStorageToken);
        xhr.setRequestHeader("X-Auth-Token", this.hubic._cachedStorageToken);
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

    for (var i = 0; i < aDir.length ; i++) {
      if (aDir[i].length !== 0) {
        remaining++;
      }
    }

    dir = '';
    for (var i = 0; i < aDir.length ; i++) {
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
    let headers = [["X-Auth-Token", this.hubic._cachedStorageToken]];
    let url = this.hubic._cachedStorageUrl + kContainerPath + dir;
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

    // Password
    if (this._password == undefined || !this._password) {
      this._password = this.getPassword(this._userName, false);

      if (this._password == "") {
        this.log.info("No password");
        return failureCallback();
      }
    }

    // WS
    let _wsFailure = function() {
      aCallback(aRequestObserver, Cr.NS_ERROR_FAILURE);
    }

    this._wsLogin(this._cachedNic, this._password, 
      function(answer) {
        this.log.info("login: " + JSON.stringify(answer));
        this._wsNewPublication(answer.session.id, this._cachedHubicId, file,
          function(answer) {
            this.log.info("newPublication: " + JSON.stringify(answer));
            this._urlsForFiles[this.file.path] = answer.indirectUrl;
            aCallback(aRequestObserver, Cr.NS_OK);
          }.bind(this), _wsFailure.bind(this)
        );
      }.bind(this), _wsFailure.bind(this)
    );
  },
};

const NSGetFactory = XPCOMUtils.generateNSGetFactory([nsHubiC]);