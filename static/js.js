"use strict";

var second = 1000;
var minute = 60 * second;

// handler for the "Copy the password" button
(function (document, window) {
	var copy_button = document.getElementById("copy");

	if (copy_button !== null) {
		copy_button.addEventListener("click", function(event) {
			var passwordBox = document.getElementById("secret");

			passwordBox.select();
			document.execCommand("copy");
			window.getSelection().removeAllRanges();

			event.preventDefault();
		});
	}
})(document, window);

// handler for the "unable to open links or emails" button
(function (document) {
	var insecure_button = document.getElementById("insecure");

	if (insecure_button !== null) {
		insecure_button.addEventListener("click", function(event) {
			var insecure_sms_form = document.getElementById("insecure_sms");
			insecure_sms_form.classList.remove("hidden");
			insecure_button.classList.add("hidden");
		});
	}
})(document);

// handler to check if db is down
(function (document, window) {
	function hideFormShowError(state) {
		var dbForm = document.getElementById("dbForm");
		var dbError = document.getElementById("dbError");

		if (state) {
			dbForm.classList.add("hidden");
			dbError.classList.remove("hidden");
		} else {
			dbForm.classList.remove("hidden");
			dbError.classList.add("hidden");
		}
	}

	function checkDB() {
		var xhr = new XMLHttpRequest();

		xhr.addEventListener("load", function() {
			hideFormShowError(false);
			window.setTimeout(checkDB, 5 * minute);

			console.log("xhr /ping success");
		});

		xhr.addEventListener("timeout", function() {
			hideFormShowError(true);
			window.setTimeout(checkDB, 30 * second);

			console.log("xhr /ping timeout");
		});

		xhr.timeout = 2 * second;
		xhr.open("GET", "/ping");
		xhr.send();
	}

	var dbForm = document.getElementById("dbForm");
	var dbError = document.getElementById("dbError");

	if (dbForm !== null && dbError !== null) {
		checkDB();
	}
})(document, window, second, minute);

// handler for sms status updates
(function (document, window) {
	function smsHideAllExcept(showClass) {
		var divs = document.getElementsByClassName("sms_status");

		for (var i = 0; i < divs.length; i++){
			if (divs[i].classList.contains(showClass)) {
				divs[i].classList.remove("hidden");
			} else {
				divs[i].classList.add("hidden");
			}
		}
	}

	function checkSmsStatus(smsId) {
		var xhr = new XMLHttpRequest();
		xhr.addEventListener("load", function() {
			console.log("xhr smsStatus success");

			var j = JSON.parse(this.responseText);
			var status = j["current_status"];

			console.log("- Current delivery status: " + status);

			var valid_states = [
				'Not sent',
				'connecting',
				'queued',
				'sent',
				'delivered',
				'undelivered',
				'failed'
			];

			var final_states = [
				'delivered',
				'undelivered',
				'failed'
			];

			var created_at = Date.parse(j.created);

			var expires_at = new Date(created_at);
			expires_at.setMinutes(expires_at.getMinutes() + 10);
			expires_at = expires_at.getTime();

			var now = new Date().getTime();

			if (now > expires_at) {
				smsHideAllExcept("sms_expired");
				console.log("# sms status DONE/EXPIRED");

				return;
			}

			var delay = 500;
			var diff = now - created_at;

			if (diff > 5 * second && diff <= 10 * second) {
				delay = second;
			} else if (diff > 10 * second && diff <= minute) {
				delay = 10 * second;
			} else if (diff > minute) {
				delay = minute;
			}

			if (valid_states.includes(status) && !final_states.includes(status)) {
				console.log("- sms status: \"" + status + "\" is in valid_states and not in final_states");

				if (status === 'Not sent') {
					smsHideAllExcept("sms_queued");
					window.setTimeout(checkSmsStatus.bind(null, smsId), delay);
				} else {
					smsHideAllExcept("sms_" + status);
					window.setTimeout(checkSmsStatus.bind(null, smsId), delay);
				}

				console.log("- sms status AGAIN delay: " + delay);

			} else if (final_states.includes(status)) {
				console.log("# sms status: \"" + status + "\" is in final_states");

				smsHideAllExcept("sms_" + status);

				console.log("# sms status DONE");

			} else {
				console.log("sms status: \"" + status + "\" is unknown");
				smsHideAllExcept("sms_error");
				console.log("# sms status DONE/ERROR");
			}
		});

		xhr.addEventListener("timeout", function() {
			console.log("# xhr smsStatus timeout");
			smsHideAllExcept("sms_error");
		});

		xhr.timeout = 10 * second;
		xhr.open("POST", window.location.href + "/" + smsId);
		xhr.send();
	}

	var smsIddiv = document.getElementById("smsId");

	if (smsIddiv !== null) {
		var smsId = smsIddiv.innerText;
		window.setTimeout(checkSmsStatus.bind(null, smsId), 500);
	}
})(document, window, second, minute);
