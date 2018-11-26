(function () {

    var maxPostBytes = 217;
    var maxReplyBytes = 184;
    var maxNameBytes = 77;
    var maxProfileTextBytes = 217;

    /**
     * @param {jQuery} $ele
     */
    MemoApp.Form.LogoutButton = function ($ele) {
        $ele.click(function () {
            delete(localStorage.WalletPassword);
        });
    };
    /**
     * @param {jQuery} $form
     */
    MemoApp.Form.PrivateMessage = function ($form) {
        var $message = $form.find("[name=message]");
        var $msgByteCount = $form.find(".message-byte-count");
        $message.on("input", function () {
            setMsgByteCount();
        });

        function setMsgByteCount() {
            var cnt = maxPostBytes - MemoApp.utf8ByteLength($message.val());
            $msgByteCount.html("[" + cnt + "]");
            if (cnt < 0) {
                $msgByteCount.addClass("red");
            } else {
                $msgByteCount.removeClass("red");
            }
        }

        setMsgByteCount();
        var submitting = false;
        $form.submit(function (e) {
            e.preventDefault();
            if (submitting) {
                return
            }

            var pubkey = $form.find("[name=pubkey]").val();
            if (pubkey.length === 0) {
                MemoApp.AddAlert("Form error, pubkey not set.");
                return;
            }

            var message = $message.val();
            if (maxPostBytes - MemoApp.utf8ByteLength(message) < 0) {
                MemoApp.AddAlert("Maximum post message is " + maxPostBytes + " bytes. Note that some characters are more than 1 byte." +
                    " Emojis are usually 4 bytes, for example.");
                return;
            }

            if (message.length === 0) {
                MemoApp.AddAlert("Must enter a message.");
                return;
            }

            var address = $form.find("[name=address]").val();
            if (address.length === 0) {
                MemoApp.AddAlert("Form error, address not set.");
                return;
            }

            var password = MemoApp.GetPassword();
            if (!password.length) {
                MemoApp.AddAlert("Password not set. Please re-enter and submit again.");
                MemoApp.ReEnterPassword(function () {
                    $form.submit();
                });
                return;
            }

            submitting = true;
            $.ajax({
                type: "POST",
                url: MemoApp.GetBaseUrl() + MemoApp.URL.MemoPrivateMessageSubmit,
                data: {
                    message: message,
                    address: address,
                    pubkey: pubkey,
                    password: password
                },
                success: function (txHash) {
                    submitting = false;
                    if (!txHash || txHash.length === 0) {
                        MemoApp.AddAlert("Server error. Please try refreshing the page.");
                        return
                    }
                    window.location = MemoApp.GetBaseUrl() + MemoApp.URL.MemoWait + "/" + txHash
                },
                error: function (xhr) {
                    submitting = false;
                    if (xhr.status === 401) {
                        MemoApp.AddAlert("Error unlocking key. " +
                            "Please verify your password is correct. " +
                            "If this problem persists, please try refreshing the page.");
                        MemoApp.ReEnterPassword(function () {
                            $form.submit();
                        });
                        return;
                    } else if (xhr.status === 402) {
                        MemoApp.AddAlert("Please make sure your account has enough funds.");
                        return;
                    }
                    var errorMessage =
                        "Error with request (response code " + xhr.status + "):\n" +
                        (xhr.responseText !== "" ? xhr.responseText + "\n" : "") +
                        "If this problem persists, try refreshing the page.";
                    MemoApp.AddAlert(errorMessage);
                }
            });
        });
    };
    /**
     * @param {jQuery} $form
     */
    MemoApp.Form.NewMemo = function ($form) {
        var $message = $form.find("[name=message]");
        var $msgByteCount = $form.find(".message-byte-count");
        $message.on("input", function () {
            setMsgByteCount();
        });

        function setMsgByteCount() {
            var cnt = maxPostBytes - MemoApp.utf8ByteLength($message.val());
            $msgByteCount.html("[" + cnt + "]");
            if (cnt < 0) {
                $msgByteCount.addClass("red");
            } else {
                $msgByteCount.removeClass("red");
            }
        }

        setMsgByteCount();
        var submitting = false;
        $form.submit(function (e) {
            e.preventDefault();
            if (submitting) {
                return
            }

            var message = $message.val();
            if (maxPostBytes - MemoApp.utf8ByteLength(message) < 0) {
                MemoApp.AddAlert("Maximum post message is " + maxPostBytes + " bytes. Note that some characters are more than 1 byte." +
                    " Emojis are usually 4 bytes, for example.");
                return;
            }

            if (message.length === 0) {
                MemoApp.AddAlert("Must enter a message.");
                return;
            }

            var password = MemoApp.GetPassword();
            if (!password.length) {
                MemoApp.AddAlert("Password not set. Please re-enter and submit again.");
                MemoApp.ReEnterPassword(function() {
                    $form.submit();
                });
                return;
            }

            submitting = true;
            $.ajax({
                type: "POST",
                url: MemoApp.GetBaseUrl() + MemoApp.URL.MemoNewSubmit,
                data: {
                    message: message,
                    password: password
                },
                success: function (txHash) {
                    submitting = false;
                    if (!txHash || txHash.length === 0) {
                        MemoApp.AddAlert("Server error. Please try refreshing the page.");
                        return
                    }
                    window.location = MemoApp.GetBaseUrl() + MemoApp.URL.MemoWait + "/" + txHash
                },
                error: function (xhr) {
                    submitting = false;
                    if (xhr.status === 401) {
                        MemoApp.AddAlert("Error unlocking key. " +
                            "Please verify your password is correct. " +
                            "If this problem persists, please try refreshing the page.");
                        MemoApp.ReEnterPassword(function() {
                            $form.submit();
                        });
                        return;
                    } else if (xhr.status === 402) {
                        MemoApp.AddAlert("Please make sure your account has enough funds.");
                        return;
                    }
                    var errorMessage =
                        "Error with request (response code " + xhr.status + "):\n" +
                        (xhr.responseText !== "" ? xhr.responseText + "\n" : "") +
                        "If this problem persists, try refreshing the page.";
                    MemoApp.AddAlert(errorMessage);
                }
            });
        });
    };
    /**
     * @param {jQuery} $form
     */
    MemoApp.Form.SetName = function ($form) {
        var $name = $form.find("[name=name]");
        var $msgByteCount = $form.find(".message-byte-count");
        $name.on("input", function () {
            setMsgByteCount();
        });

        function setMsgByteCount() {
            var cnt = maxNameBytes - MemoApp.utf8ByteLength($name.val());
            $msgByteCount.html("[" + cnt + "]");
            if (cnt < 0) {
                $msgByteCount.addClass("red");
            } else {
                $msgByteCount.removeClass("red");
            }
        }

        setMsgByteCount();
        var submitting = false;
        $form.submit(function (e) {
            e.preventDefault();
            if (submitting) {
                return
            }

            var name = $name.val();
            if (maxNameBytes - MemoApp.utf8ByteLength(name) < 0) {
                MemoApp.AddAlert("Maximum name is " + maxNameBytes + " bytes. Note that some characters are more than 1 byte." +
                    " Emojis are usually 4 bytes, for example.");
                return;
            }

            if (name.length === 0) {
                MemoApp.AddAlert("Must enter a name.");
                return;
            }

            var password = MemoApp.GetPassword();
            if (!password.length) {
                MemoApp.AddAlert("Password not set. Please re-enter and submit again.");
                MemoApp.ReEnterPassword(function() {
                    $form.submit();
                });
                return;
            }

            submitting = true;
            $.ajax({
                type: "POST",
                url: MemoApp.GetBaseUrl() + MemoApp.URL.MemoSetNameSubmit,
                data: {
                    name: name,
                    password: password
                },
                success: function (txHash) {
                    submitting = false;
                    if (!txHash || txHash.length === 0) {
                        MemoApp.AddAlert("Server error. Please try refreshing the page.");
                        return
                    }
                    window.location = MemoApp.GetBaseUrl() + MemoApp.URL.MemoWait + "/" + txHash
                },
                error: function (xhr) {
                    submitting = false;
                    if (xhr.status === 401) {
                        MemoApp.AddAlert("Error unlocking key. " +
                            "Please verify your password is correct. " +
                            "If this problem persists, please try refreshing the page.");
                        MemoApp.ReEnterPassword(function() {
                            $form.submit();
                        });
                        return;
                    } else if (xhr.status === 402) {
                        MemoApp.AddAlert("Please make sure your account has enough funds.");
                        return;
                    }
                    var errorMessage =
                        "Error with request (response code " + xhr.status + "):\n" +
                        (xhr.responseText !== "" ? xhr.responseText + "\n" : "") +
                        "If this problem persists, try refreshing the page.";
                    MemoApp.AddAlert(errorMessage);
                }
            });
        });
    };
    /**
     * @param {jQuery} $form
     */
    MemoApp.Form.SetProfilePic = function ($form) {
        var $url = $form.find("[name=url]");
        var $submit = $('#set-profile-pic-submit');
        var $cancel = $('#set-profile-pic-cancel');
        var $broadcasting = $('#set-profile-pic-broadcasting');
        var $msgByteCount = $form.find(".message-byte-count");
        $url.on("input", function () {
            setMsgByteCount();
        });

        function setMsgByteCount() {
            var cnt = maxNameBytes - MemoApp.utf8ByteLength($url.val());
            $msgByteCount.html("[" + cnt + "]");
            if (cnt < 0) {
                $msgByteCount.addClass("red");
            } else {
                $msgByteCount.removeClass("red");
            }
        }

        setMsgByteCount();
        var submitting = false;
        $form.submit(function (e) {
            e.preventDefault();

            if (submitting) {
                return
            }

            var url = $url.val();
            if (maxPostBytes - MemoApp.utf8ByteLength(url) < 0) {
                MemoApp.AddAlert("Maximum name is " + maxNameBytes + " bytes. Note that some characters are more than 1 byte." +
                    " Emojis are usually 4 bytes, for example.");
                return;
            }

            if (url.length === 0) {
                MemoApp.AddAlert("Must enter a URL.");
                return;
            }
            var imgurJpg = /^https:\/\/i\.imgur\.com\/[a-zA-Z0-9]+\.(jpg|png)$/;
            var imgurLink = /^https:\/\/imgur\.com\/[a-zA-Z0-9]+$/;
            var imgurJpgErroMsg = "Please enter an imgur URL in the form https://imgur.com/abcd or https://i.imgur.com/abcd.jpg";
            if (!imgurJpg.test(url) && !imgurLink.test(url)) {
                MemoApp.AddAlert(imgurJpgErroMsg);
                return;
            }

            var password = MemoApp.GetPassword();
            if (!password.length) {
                MemoApp.AddAlert("Password not set. Please re-enter and submit again.");
                MemoApp.ReEnterPassword(function() {
                    $form.submit();
                });
                return;
            }

            $submit.prop('disabled', true);
            $url.prop('disabled', true);
            $broadcasting.removeClass('hidden');
            $cancel.hide();

            submitting = true;
            $.ajax({
                type: "POST",
                url: MemoApp.GetBaseUrl() + MemoApp.URL.MemoSetProfilePicSubmit,
                data: {
                    url: url,
                    password: password
                },
                success: function (txHash) {
                    submitting = false;
                    if (!txHash || txHash.length === 0) {
                        MemoApp.AddAlert("Server error. Please try refreshing the page.");
                        $submit.prop('disabled', false);
                        $url.prop('disabled', false);
                        $broadcasting.addClass('hidden');
                        $cancel.show()
                        return
                    }
                    window.location = MemoApp.GetBaseUrl() + MemoApp.URL.MemoWait + "/" + txHash
                },
                error: function (xhr) {
                    submitting = false;
                    if (xhr.status === 401) {
                        MemoApp.AddAlert("Error unlocking key. " +
                            "Please verify your password is correct. " +
                            "If this problem persists, please try refreshing the page.");
                        MemoApp.ReEnterPassword(function() {
                            $form.submit();
                        });
                    } else if (xhr.status === 402) {
                        MemoApp.AddAlert("Please make sure your account has enough funds.");
                        return;
                    } else if (xhr.status === 422) {
                        MemoApp.AddAlert(imgurJpgErroMsg);
                    } else {
                        var errorMessage =
                            "Error with request (response code " + xhr.status + "):\n" +
                            (xhr.responseText !== "" ? xhr.responseText + "\n" : "") +
                            "If this problem persists, try refreshing the page.";
                        MemoApp.AddAlert(errorMessage);
                    }
                    $submit.prop('disabled', false);
                    $url.prop('disabled', false);
                    $broadcasting.addClass('hidden');
                    $cancel.show()
                }
            });
        });
    };
    /**
     * @param {jQuery} $form
     */
    MemoApp.Form.SetProfile = function ($form) {
        var $profile = $form.find("[name=profile]");
        var $msgByteCount = $form.find(".message-byte-count");
        $profile.on("input", function () {
            setMsgByteCount();
        });

        function setMsgByteCount() {
            var cnt = maxProfileTextBytes - MemoApp.utf8ByteLength($profile.val());
            $msgByteCount.html("[" + cnt + "]");
            if (cnt < 0) {
                $msgByteCount.addClass("red");
            } else {
                $msgByteCount.removeClass("red");
            }
        }

        setMsgByteCount();

        var submitting = false;
        $form.submit(function (e) {
            e.preventDefault();
            if (submitting) {
                return
            }

            var profile = $profile.val();
            if (maxProfileTextBytes - MemoApp.utf8ByteLength(profile) < 0) {
                MemoApp.AddAlert("Maximum profile text is " + maxProfileTextBytes + " bytes. Note that some characters are more than 1 byte." +
                    " Emojis are usually 4 bytes, for example.");
                return;
            }

            if (profile.length === 0) {
                if (!confirm("Are you sure you want to set an empty profile?")) {
                    return;
                }
            }

            var password = MemoApp.GetPassword();
            if (!password.length) {
                MemoApp.AddAlert("Password not set. Please re-enter and submit again.");
                MemoApp.ReEnterPassword(function() {
                    $form.submit();
                });
                return;
            }

            submitting = true;
            $.ajax({
                type: "POST",
                url: MemoApp.GetBaseUrl() + MemoApp.URL.MemoSetProfileSubmit,
                data: {
                    profile: profile,
                    password: password
                },
                success: function (txHash) {
                    submitting = false;
                    if (!txHash || txHash.length === 0) {
                        MemoApp.AddAlert("Server error. Please try refreshing the page.");
                        return
                    }
                    window.location = MemoApp.GetBaseUrl() + MemoApp.URL.MemoWait + "/" + txHash
                },
                error: function (xhr) {
                    submitting = false;
                    if (xhr.status === 401) {
                        MemoApp.AddAlert("Error unlocking key. " +
                            "Please verify your password is correct. " +
                            "If this problem persists, please try refreshing the page.");
                        MemoApp.ReEnterPassword(function() {
                            $form.submit();
                        });
                        return;
                    } else if (xhr.status === 402) {
                        MemoApp.AddAlert("Please make sure your account has enough funds.");
                        return;
                    }
                    var errorMessage =
                        "Error with request (response code " + xhr.status + "):\n" +
                        (xhr.responseText !== "" ? xhr.responseText + "\n" : "") +
                        "If this problem persists, try refreshing the page.";
                    MemoApp.AddAlert(errorMessage);
                }
            });
        });
    };
    /**
     * @param {jQuery} $form
     */
    MemoApp.Form.Follow = function ($form) {
        var submitting = false;
        $form.submit(function (e) {
            e.preventDefault();
            if (submitting) {
                return
            }

            var address = $form.find("[name=address]").val();
            if (address.length === 0) {
                MemoApp.AddAlert("Form error, address not set.");
                return;
            }

            var password = MemoApp.GetPassword();
            if (!password.length) {
                MemoApp.AddAlert("Password not set. Please re-enter and submit again.");
                MemoApp.ReEnterPassword(function() {
                    $form.submit();
                });
                return;
            }

            submitting = true;
            $.ajax({
                type: "POST",
                url: MemoApp.GetBaseUrl() + MemoApp.URL.MemoFollowSubmit,
                data: {
                    address: address,
                    password: password
                },
                success: function (txHash) {
                    submitting = false;
                    if (!txHash || txHash.length === 0) {
                        MemoApp.AddAlert("Server error. Please try refreshing the page.");
                        return
                    }
                    window.location = MemoApp.GetBaseUrl() + MemoApp.URL.MemoWait + "/" + txHash
                },
                error: function (xhr) {
                    submitting = false;
                    if (xhr.status === 401) {
                        MemoApp.AddAlert("Error unlocking key. " +
                            "Please verify your password is correct. " +
                            "If this problem persists, please try refreshing the page.");
                        MemoApp.ReEnterPassword(function() {
                            $form.submit();
                        });
                        return;
                    } else if (xhr.status === 402) {
                        MemoApp.AddAlert("Please make sure your account has enough funds.");
                        return;
                    }
                    var errorMessage =
                        "Error with request (response code " + xhr.status + "):\n" +
                        (xhr.responseText !== "" ? xhr.responseText + "\n" : "") +
                        "If this problem persists, try refreshing the page.";
                    MemoApp.AddAlert(errorMessage);
                }
            });
        });
    };

    /**
     * @param {jQuery} $form
     */
    MemoApp.Form.Unfollow = function ($form) {
        var submitting = false;
        $form.submit(function (e) {
            e.preventDefault();
            if (submitting) {
                return
            }

            var address = $form.find("[name=address]").val();
            if (address.length === 0) {
                MemoApp.AddAlert("Form error, address not set.");
                return;
            }

            var password = MemoApp.GetPassword();
            if (!password.length) {
                MemoApp.AddAlert("Password not set. Please re-enter and submit again.");
                MemoApp.ReEnterPassword(function() {
                    $form.submit();
                });
                return;
            }

            submitting = true;
            $.ajax({
                type: "POST",
                url: MemoApp.GetBaseUrl() + MemoApp.URL.MemoUnfollowSubmit,
                data: {
                    address: address,
                    password: password
                },
                success: function (txHash) {
                    submitting = false;
                    if (txHash === undefined || txHash.length === 0) {
                        MemoApp.AddAlert("Server error. Please try refreshing the page.");
                        return
                    }
                    window.location = MemoApp.GetBaseUrl() + MemoApp.URL.MemoWait + "/" + txHash
                },
                error: function (xhr) {
                    submitting = false;
                    if (xhr.status === 401) {
                        MemoApp.AddAlert("Error unlocking key. " +
                            "Please verify your password is correct. " +
                            "If this problem persists, please try refreshing the page.");
                        MemoApp.ReEnterPassword(function() {
                            $form.submit();
                        });
                        return;
                    } else if (xhr.status === 402) {
                        MemoApp.AddAlert("Please make sure your account has enough funds.");
                        return;
                    }
                    var errorMessage =
                        "Error with request (response code " + xhr.status + "):\n" +
                        (xhr.responseText !== "" ? xhr.responseText + "\n" : "") +
                        "If this problem persists, try refreshing the page.";
                    MemoApp.AddAlert(errorMessage);
                }
            });
        });
    };
    /**
     * @param {jQuery} $form
     */
    MemoApp.Form.Like = function ($form) {
        var submitting = false;
        $form.submit(function (e) {
            e.preventDefault();
            if (submitting) {
                return
            }

            var txHash = $form.find("[name=tx-hash]").val();
            if (txHash.length === 0) {
                MemoApp.AddAlert("Form error, tx hash not set.");
                return;
            }

            var tip = $form.find("[name=tip]").val();
            if (tip.length !== 0 && tip < 546) {
                MemoApp.AddAlert("Must enter a tip greater than 546 (the minimum dust limit).");
                return;
            }

            var password = MemoApp.GetPassword();
            if (!password.length) {
                MemoApp.AddAlert("Password not set. Please re-enter and submit again.");
                MemoApp.ReEnterPassword(function() {
                    $form.submit();
                });
                return;
            }

            submitting = true;
            $.ajax({
                type: "POST",
                url: MemoApp.GetBaseUrl() + MemoApp.URL.MemoLikeSubmit,
                data: {
                    txHash: txHash,
                    tip: tip,
                    password: password
                },
                success: function (txHash) {
                    submitting = false;
                    if (!txHash || txHash.length === 0) {
                        MemoApp.AddAlert("Server error. Please try refreshing the page.");
                        return
                    }
                    window.location = MemoApp.GetBaseUrl() + MemoApp.URL.MemoWait + "/" + txHash
                },
                error: function (xhr) {
                    submitting = false;
                    if (xhr.status === 401) {
                        MemoApp.AddAlert("Error unlocking key. " +
                            "Please verify your password is correct. " +
                            "If this problem persists, please try refreshing the page.");
                        MemoApp.ReEnterPassword(function() {
                            $form.submit();
                        });
                        return;
                    } else if (xhr.status === 402) {
                        MemoApp.AddAlert("Please make sure your account has enough funds.");
                        return;
                    }
                    var errorMessage =
                        "Error with request (response code " + xhr.status + "):\n" +
                        (xhr.responseText !== "" ? xhr.responseText + "\n" : "") +
                        "If this problem persists, try refreshing the page.";
                    MemoApp.AddAlert(errorMessage);
                }
            });
        });
    };
    /**
     * @param {string} txHash
     * @param {string} formHash
     * @param {boolean} threaded
     * @param {boolean} showParent
     */
    MemoApp.Form.ReplyMemo = function (txHash, formHash, threaded, showParent) {
        var $post = $("#post-" + formHash);
        var $form = $("#reply-form-" + formHash);
        var $replyCancel = $("#reply-cancel-" + formHash);
        var $message = $form.find("[name=message]");
        var $msgByteCount = $form.find(".message-byte-count");
        var $replyLink = $("#reply-link-" + formHash);
        var $broadcasting = $post.find(".broadcasting:eq(0)");
        var $creating = $post.find(".creating:eq(0)");
        $message.on("input", function () {
            setMsgByteCount();
        });

        function setMsgByteCount() {
            var cnt = maxReplyBytes - MemoApp.utf8ByteLength($message.val());
            $msgByteCount.html("[" + cnt + "]");
            if (cnt < 0) {
                $msgByteCount.addClass("red");
            } else {
                $msgByteCount.removeClass("red");
            }
        }

        $replyCancel.click(function (e) {
            e.preventDefault();
            $form.addClass("hidden");
        });

        setMsgByteCount();
        var submitting = false;
        $form.submit(function (e) {
            e.preventDefault();
            if (submitting) {
                return
            }

            var message = $message.val();
            if (maxReplyBytes - MemoApp.utf8ByteLength(message) < 0) {
                MemoApp.AddAlert("Maximum reply message is " + maxReplyBytes + " bytes. Note that some characters are more than 1 byte. " +
                    "Emojis are usually 4 bytes, for example.");
                return;
            }

            if (message.length === 0) {
                MemoApp.AddAlert("Must enter a message.");
                return;
            }

            var password = MemoApp.GetPassword();
            if (!password.length) {
                MemoApp.AddAlert("Password not set. Please re-enter and submit again.");
                MemoApp.ReEnterPassword(function() {
                    $form.submit();
                });
                return;
            }

            $creating.removeClass("hidden");
            $replyLink.hide();
            $form.hide();

            submitting = true;
            $.ajax({
                type: "POST",
                url: MemoApp.GetBaseUrl() + MemoApp.URL.MemoReplySubmit,
                data: {
                    txHash: txHash,
                    message: message,
                    password: password
                },
                success: function (replyTxHash) {
                    submitting = false;
                    if (!replyTxHash || replyTxHash.length === 0) {
                        MemoApp.AddAlert("Server error. Please try refreshing the page.");
                        return
                    }
                    $creating.addClass("hidden");
                    $broadcasting.removeClass("hidden");
                    $.ajax({
                        type: "POST",
                        url: MemoApp.GetBaseUrl() + MemoApp.URL.MemoWaitSubmit,
                        data: {
                            txHash: replyTxHash,
                            showParent: showParent
                        },
                        success: function () {
                            submitting = false;
                            var url = MemoApp.URL.MemoPostAjax;
                            if (threaded) {
                                url = MemoApp.URL.MemoPostThreadedAjax
                            }
                            $.ajax({
                                url: MemoApp.GetBaseUrl() + url + "/" + txHash,
                                data: {
                                    showParent: showParent
                                },
                                success: function (html) {
                                    $("#post-" + formHash).replaceWith(html);
                                    MemoApp.ReloadTwitter();
                                },
                                error: function (xhr) {
                                    MemoApp.AddAlert("error getting post via ajax (status: " + xhr.status + ")");
                                }
                            });
                        },
                        error: function () {
                            submitting = false;
                            $broadcasting.addClass("hidden");
                            console.log("Error waiting for transaction to broadcast.");
                        }
                    });
                },
                error: function (xhr) {
                    submitting = false;
                    $creating.addClass("hidden");
                    $replyLink.show();
                    $form.show();
                    if (xhr.status === 401) {
                        MemoApp.AddAlert("Error unlocking key. " +
                            "Please verify your password is correct. " +
                            "If this problem persists, please try refreshing the page.");
                        MemoApp.ReEnterPassword(function() {
                            $form.submit();
                        });
                        return;
                    } else if (xhr.status === 402) {
                        MemoApp.AddAlert("Please make sure your account has enough funds.");
                        return;
                    }
                    var errorMessage =
                        "Error with request (response code " + xhr.status + "):\n" +
                        (xhr.responseText !== "" ? xhr.responseText + "\n" : "") +
                        "If this problem persists, try refreshing the page.";
                    MemoApp.AddAlert(errorMessage);
                }
            });
        });
    };

    /**
     * @param {jQuery} $form
     * @param {jQuery} $notify
     * @param {jQuery} $title
     */
    MemoApp.Form.Wait = function ($form, $notify, $title) {
        var text = "Broadcasting transaction";
        var dots = 1;
        setInterval(function () {
            $title.html(text + Array(dots).join("."));
            dots++;
            if (dots > 5) {
                dots = 1;
            }
        }, 750);
        $form.submit(function (e) {
            e.preventDefault();
            var txHash = $form.find("[name=tx-hash]").val();
            if (txHash.length === 0) {
                MemoApp.AddAlert("Form error, tx hash not set.");
                return;
            }

            $.ajax({
                type: "POST",
                url: MemoApp.GetBaseUrl() + MemoApp.URL.MemoWaitSubmit,
                data: {
                    txHash: txHash
                },
                success: function (url) {
                    if (!url || url.length === 0) {
                        MemoApp.AddAlert("Error with broadcast. Please try again.");
                        return
                    }
                    window.location = MemoApp.GetBaseUrl() + url
                },
                error: function () {
                    $notify.html(
                        "Transaction propagation taking longer than normal. " +
                        "You can continue waiting or try again. " +
                        "This page will automatically redirect when transaction has propagated."
                    );
                    $form.submit();
                }
            });
        });
        $form.submit();
    };

    /**
     * @param {string} formHash
     */
    MemoApp.Form.ReplyLink = function (formHash) {
        var $replyLink = $("#reply-link-" + formHash);
        var $replyForm = $("#reply-form-" + formHash);
        $replyLink.click(function (e) {
            e.preventDefault();
            $replyForm.removeClass("hidden");
        });
    };

    /**
     * @param {string} txHash
     * @param {string} formHash
     * @param {boolean} threaded
     * @param {boolean} showParent
     */
    MemoApp.Form.NewLike = function (txHash, formHash, threaded, showParent) {
        var $like = $("#like-" + formHash);
        var $likeLink = $("#like-link-" + formHash);
        var $likeCancel = $("#like-cancel-" + formHash);
        var $likeInfo = $("#like-info-" + formHash);
        var $likeForm = $("#like-form-" + formHash);
        var $creating = $like.parent().find(".creating:eq(0)");
        var $broadcasting = $like.parent().find(".broadcasting:eq(0)");

        $likeLink.click(function (e) {
            e.preventDefault();
            $likeInfo.hide();
            $likeForm.removeClass("hidden");
        });
        $likeCancel.click(function (e) {
            e.preventDefault();
            $likeInfo.show();
            $likeForm.addClass("hidden");
        });

        var submitting = false;
        $likeForm.submit(function (e) {
            e.preventDefault();
            if (submitting) {
                return
            }

            var tip = $likeForm.find("[name=tip]").val();
            if (tip.length !== 0 && tip < 546) {
                MemoApp.AddAlert("Must enter a tip greater than 546 (the minimum dust limit).");
                return;
            }

            var password = MemoApp.GetPassword();
            if (!password.length) {
                MemoApp.AddAlert("Password not set. Please re-enter and submit again.");
                MemoApp.ReEnterPassword(function() {
                    $likeForm.submit();
                });
                return;
            }

            $creating.removeClass("hidden");
            $likeForm.hide();

            submitting = true;
            $.ajax({
                type: "POST",
                url: MemoApp.GetBaseUrl() + MemoApp.URL.MemoLikeSubmit,
                data: {
                    txHash: txHash,
                    tip: tip,
                    password: password
                },
                success: function (likeTxHash) {
                    submitting = false;
                    if (!likeTxHash || likeTxHash.length === 0) {
                        MemoApp.AddAlert("Server error. Please try refreshing the page.");
                        return
                    }
                    $creating.addClass("hidden");
                    $broadcasting.removeClass("hidden");
                    $.ajax({
                        type: "POST",
                        url: MemoApp.GetBaseUrl() + MemoApp.URL.MemoWaitSubmit,
                        data: {
                            txHash: likeTxHash
                        },
                        success: function () {
                            submitting = false;
                            var url = MemoApp.URL.MemoPostAjax;
                            if (threaded) {
                                url = MemoApp.URL.MemoPostThreadedAjax
                            }
                            $.ajax({
                                url: MemoApp.GetBaseUrl() + url + "/" + txHash,
                                data: {
                                    showParent: showParent
                                },
                                success: function (html) {
                                    $("#post-" + formHash).replaceWith(html);
                                    MemoApp.ReloadTwitter();
                                },
                                error: function (xhr) {
                                    MemoApp.AddAlert("error getting post via ajax (status: " + xhr.status + ")");
                                }
                            });
                        },
                        error: function () {
                            submitting = false;
                            $broadcasting.addClass("hidden");
                            console.log("Error waiting for transaction to broadcast.");
                        }
                    });
                },
                error: function (xhr) {
                    submitting = false;
                    $creating.addClass("hidden");
                    $broadcasting.addClass("hidden");
                    $likeForm.show();
                    if (xhr.status === 401) {
                        MemoApp.AddAlert("Error unlocking key. " +
                            "Please verify your password is correct. " +
                            "If this problem persists, please try refreshing the page.");
                        MemoApp.ReEnterPassword(function() {
                            $likeForm.submit();
                        });
                        return;
                    } else if (xhr.status === 402) {
                        MemoApp.AddAlert("Please make sure your account has enough funds.");
                        return;
                    }
                    var errorMessage =
                        "Error with request (response code " + xhr.status + "):\n" +
                        (xhr.responseText !== "" ? xhr.responseText + "\n" : "") +
                        "If this problem persists, try refreshing the page.";
                    MemoApp.AddAlert(errorMessage);
                }
            });
        });
    };

    /**
     * @param {jQuery} $likesButton
     * @param {jQuery} $likes
     */
    MemoApp.Form.LikesToggle = function ($likesButton, $likes) {
        $likesButton.click(function (e) {
            e.preventDefault();
            if ($likes.is(":visible")) {
                $likes.hide();
                $likesButton.html("Show");
            } else {
                $likes.show();
                $likesButton.html("Hide");
            }
        });
    };

    /**
     * @param {jQuery} $moreReplies
     * @param {string} txHash
     * @param {number} offset
     */
    MemoApp.Form.LoadMoreReplies = function ($moreReplies, txHash, offset) {
        var $link = $moreReplies.find("a");
        $link.click(function (e) {
            e.preventDefault();
            $.ajax({
                url: MemoApp.GetBaseUrl() + MemoApp.URL.MemoPostMoreThreadedAjax,
                data: {
                    txHash: txHash,
                    offset: offset + 25
                },
                success: function (html) {
                    $moreReplies.replaceWith(html);
                    MemoApp.ReloadTwitter();
                },
                error: function () {
                    console.log("Error loading more replies.");
                }
            });
        });
    };
    /**
     * @param {jQuery} @param {jQuery} $link
     */
    MemoApp.Form.PrivateMessageLink = function ($link) {
        $link.click(function (e) {
            e.preventDefault();
            var $form = $('<form action="' + MemoApp.URL.MemoPrivateMessages + '" method="post">' +
                '<input type="hidden" name="password" value="' + MemoApp.GetPassword() + '">' +
                '</form>');
            $('body').append($form);
            $form.submit();
        });
    };

    /**
     * @param {jQuery} @param {jQuery} $link
     */
    MemoApp.Form.PostPassword = function ($link) {
        $link.click(function (e) {
            e.preventDefault();
            var $form = $('<form action="' + window.location + '" method="post">' +
                '<input type="hidden" name="password" value="' + MemoApp.GetPassword() + '">' +
                '</form>');
            $('body').append($form);
            $form.submit();
        });
    };

    /**
     * @param {jQuery} @param {jQuery} $link
     */
    MemoApp.Form.PrivateMessagePage = function ($link) {
        $link.click(function (e) {
            e.preventDefault();
            var $form = $('<form action="' + this.href + '" method="post">' +
                '<input type="hidden" name="password" value="' + MemoApp.GetPassword() + '">' +
                '</form>');
            $('body').append($form);
            $form.submit();
        });
    };
})();
