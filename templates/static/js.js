"use strict";

const second = 1000;
const minute = 60 * second;

// handler for the "Copy the password" button
(function (document, window) {
	function disableRecursively(rootElem) {
		if (!rootElem) {
			return;
		}

		if (rootElem instanceof HTMLCollection) {
			for (let i = 0; i < rootElem.length; i++) {
				disableRecursively(rootElem[i]);
			}

			return;
		}

		if (rootElem.children) {
			for (let i = 0; i < rootElem.children.length; i++) {
				disableRecursively(rootElem.children[i]);
			}
		}

		rootElem.disabled = true;
		rootElem.readonly = true;

		if (rootElem.tagName === 'H2') {
			rootElem.classList.add('disabled');
		}
	}

	const copy_button = document.getElementById("copy");

	if (copy_button !== null) {
		copy_button.addEventListener("click", function(event) {
			const passwordBox = document.getElementById("secret");

			passwordBox.type = 'text';

			passwordBox.select();
			document.execCommand("copy");
			window.getSelection().removeAllRanges();

			// Disable other form input fields since we selected this field
			disableRecursively(document.getElementsByClassName("choice"));

			event.preventDefault();
		});
	}
})(document, window);

// handler to check if db is down
(function (document, window) {
	function hideFormShowError(state) {
		const dbForm = document.getElementById("dbForm");
		const dbError = document.getElementById("dbError");

		if (state) {
			dbForm.classList.add("hidden");
			dbError.classList.remove("hidden");
		} else {
			dbForm.classList.remove("hidden");
			dbError.classList.add("hidden");
		}
	}

	function checkDB() {
		const xhr = new XMLHttpRequest();

		xhr.addEventListener("load", function() {
			if (this.status != 200) {
				hideFormShowError(true);
				window.setTimeout(checkDB, minute);

				console.log("xhr /ping error");
			} else {
				hideFormShowError(false);
				window.setTimeout(checkDB, 5 * minute);

				console.log("xhr /ping success");
			}
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

	const dbForm = document.getElementById("dbForm");
	const dbError = document.getElementById("dbError");

	if (dbForm !== null && dbError !== null) {
		checkDB();
	}
})(document, window, second, minute);
