<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<title>Sign In</title>
<link rel='StyleSheet' href='css/common.css' type='text/css'>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
</head>
<body>
	<div class="container">

		<p class="actionDesc">If you already have an active account, enter
			your email address and password to sign in.
		<form name="signin" action="#">
			<table class="login">
				<tr>
					<th><label for="EMAIL">Email address:</label></th>
					<td><input id="signinInputEmail" name="EMAIL" type="email"
						size=40 maxlength=128 autofocus="true"></input>
				<tr>
					<th><label for="PASSWORD">Password:</label></th>
					<td><input id="signinInputPassword" name="PASSWORD"
						type="password"></input>
				<tr>
					<td>&nbsp;</td>
					<td>
						<button id="signinButton" class="preferredButton" type="button">Sign
							In</button>
					</td>
			</table>
		</form>

		<p class="actionDesc">If you don't already have an account, enter
			your email address here. You will receive an email with a temporary
			password within a few moments.
		<form name="signup" action="#">
			<table class="login">
				<tr>
					<th><label for="EMAIL">Email address:</label></th>
					<td><input id="signupInputEmail" name="EMAIL" type="email"
						size=40 maxlength=128></input>
				<tr>
					<td>&nbsp;</td>
					<td>
						<button id="signupButton" class="secondaryButton" type="button">Sign
							Up</button>
					</td>
			</table>
		</form>

	</div>

	<script type="text/javascript"
		src="https://code.jquery.com/jquery-3.1.1.min.js"></script>
	<script type="text/javascript">
		$(document)
				.ready(
						function() {

							$("#signinButton")
									.click(
											function(event) {
												doSignIn($("#signinInputEmail")
														.val(), $(
														"#signinInputPassword")
														.val());
												event.preventDefault();
											});

							$("#signupButton").click(function(event) {
								doSignUp($("#signupInputEmail").val());
								event.preventDefault();
							});

							function doSignIn(email, password) {
								console.log("about to sign in; username = "
										+ email);
								$.post("signin", {
									EMAIL : email,
									PASSWORD : password
								}).done(handleSignInResult).fail(function() {
									alert("error when attempting to sign-in");
								});
							}

							function handleSignInResult(response) {
								console.log("signin complete, response = "
										+ response)
								if (response === "INVALID_REQUEST") {
									alert("you didn't fill in both fields!");
								} else if (response === "NO_SUCH_USER") {
									alert("incorrect userid or password -- do you need to sign up?");
								} else if (response === "LOGGED_IN") {
									window.location
											.replace("validated-page.html")
								} else if (response === "FORCE_PASSWORD_CHANGE") {
									window.location
											.replace("confirm-signup.html")
								} else {
									alert("unknown response code: " + response);
								}
							}

							function doSignUp(email) {
								console.log("about to sign up; username = "
										+ email);
								$.post("signup", {
									EMAIL : email
								}).done(handleSignUpResult).fail(function() {
									alert("error when attempting to sign-up");
								});
							}

							function handleSignUpResult(response) {
								console.log("signin complete, response = "
										+ response)
								if (response === "INVALID_REQUEST") {
									alert("you didn't fill in the email address!");
								} else if (response === "USER_ALREADY_EXISTS") {
									alert("this user already exists!");
								} else if (response === "USER_CREATED") {
									window.location
											.replace("confirm-signup.html")
								} else {
									alert("unknown response code: " + response);
								}
							}
						});
	</script>
</body>
</html>
