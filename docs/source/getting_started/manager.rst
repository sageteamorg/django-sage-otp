Manager Layer
=============

The service layer contains the core logic for generating, validating, and managing OTPs. Below are detailed descriptions of the key classes and their methods, including all arguments and usage examples.

OTPManager Class
----------------

The `OTPManager` class provides methods for handling One-Time Password (OTP) operations, such as generating, validating, and managing OTPs for user authentication.

Methods
^^^^^^^

- `get_otp(identifier: str, reason: str) -> OTP`
  Retrieves an active OTP for a user based on the identifier (username) and reason (e.g., login or password reset).

  **Arguments:**
  - `identifier`: The username of the user.
  - `reason`: The reason for OTP generation (e.g., 'login', 'password reset').

  **Returns:**
  - `OTP`: The active OTP object.

  **Raises:**
  - `OTPDoesNotExists`: If no active OTP exists for the given user and reason.
  - `OTPException`: If multiple active OTPs exist for the given user and reason.

- `get_or_create_otp(identifier: str, reason: str) -> tuple[OTP, bool]`
  Retrieves an existing OTP or creates a new one if none is found.

  **Arguments:**
  - `identifier`: The username of the user.
  - `reason`: The reason for OTP generation.

  **Returns:**
  - `OTP`: The OTP instance.
  - `created`: Boolean indicating whether the OTP was newly created.

- `reset_otp(otp: OTP) -> OTP`
  Resets the OTP, generating a new token and resetting the failed attempt count.

  **Arguments:**
  - `otp`: The OTP instance to be reset.

  **Returns:**
  - `OTP`: The updated OTP instance.

- `check_otp_last_sent_at(otp: OTP) -> Optional[Dict[str, bool]]`
  Checks if the user can request a resend of the OTP based on the time elapsed since the last OTP was sent.

  **Arguments:**
  - `otp`: The OTP instance.

  **Returns:**
  - `Optional[Dict[str, bool]]`: A dictionary indicating whether the OTP can be resent and the remaining time until resend is allowed.

- `send_otp(identifier: str, reason: str) -> Optional[Dict[str, Union[bool, int]]]`
  Sends an OTP to the user, either via email or SMS.

  **Arguments:**
  - `identifier`: The username or email of the user.
  - `reason`: The reason for OTP generation.

  **Returns:**
  - `Optional[Dict[str, Union[bool, int]]]`: None if the OTP is sent successfully, or lock status if resending is restricted.

- `check_otp(identifier: str, token: str, reason: str) -> Union[Dict[str, bool], NoReturn]`
  Validates the provided OTP for the given user and reason.

  **Arguments:**
  - `identifier`: The username of the user.
  - `token`: The OTP token provided by the user.
  - `reason`: The reason for OTP generation.

  **Returns:**
  - `Union[Dict[str, bool], NoReturn]`: A dictionary indicating whether the OTP is correct. Raises `OTPExpiredException` if the OTP has expired.

OtpBusinessLogicLayer Class
---------------------------

The `OtpBusinessLogicLayer` class extends `OTPManager` and provides additional methods for specific OTP scenarios like login, password reset, and phone number activation.

Methods
^^^^^^^

- `send_email_activation_otp(email: str) -> Optional[Dict[str, Union[bool, int]]]`
  Sends an OTP for email activation.

  **Arguments:**
  - `email`: The email address of the user.

  **Returns:**
  - `Optional[Dict[str, Union[bool, int]]]`: Lock status and remaining time, if locked.

- `send_login_otp(identifier: str) -> Optional[Dict[str, Union[bool, int]]]`
  Sends an OTP for login.

  **Arguments:**
  - `identifier`: The username or email of the user.

  **Returns:**
  - `Optional[Dict[str, Union[bool, int]]]`: Lock status and remaining time, if locked.

- `send_reset_password_otp(identifier: str) -> Optional[Dict[str, Union[bool, int]]]`
  Sends an OTP for password reset.

  **Arguments:**
  - `identifier`: The username or email of the user.

  **Returns:**
  - `Optional[Dict[str, Union[bool, int]]]`: Lock status and remaining time, if locked.

- `verify_otp(identifier: str, token: str, reason: str) -> Union[Dict[str, bool], NoReturn]`
  Validates the provided OTP for login, password reset, or any other reason.

  **Arguments:**
  - `identifier`: The username or email of the user.
  - `token`: The OTP token provided by the user.
  - `reason`: The reason for OTP generation (e.g., login, password reset).

  **Returns:**
  - `Union[Dict[str, bool], NoReturn]`: A dictionary indicating whether the OTP is correct.

Example Usage
^^^^^^^^^^^^^

.. code-block:: python

    from sage_otp.service.manager import OTPManager

    # Create an instance of OTPManager
    otp_manager = OTPManager()

    # Generate or retrieve an OTP for login
    otp, created = otp_manager.get_or_create_otp(identifier="testuser", reason="login")

    # Validate the OTP provided by the user
    otp_manager.check_otp(identifier="testuser", token="123456", reason="login")

    # Reset an existing OTP
    otp_manager.reset_otp(otp)
