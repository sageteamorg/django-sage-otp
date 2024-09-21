Service Layer
=============

The service layer contains the core logic for generating, validating, and managing OTPs. Below are detailed descriptions of the key methods in the `OTPService` class, including arguments and usage examples.

OTPService Class
----------------

The `OTPService` class provides methods for handling One-Time Password (OTP) operations, such as generating, verifying, and expiring OTPs for user authentication.

Methods
^^^^^^^

- `get_otp(user: User, reason: str) -> OTP`
  Retrieves an active OTP for a given user and reason.

  **Arguments:**
  - `user`: The user instance for which the OTP is being retrieved.
  - `reason`: The reason for which the OTP is being retrieved (e.g., login or password reset).

  **Returns:**
  - `OTP`: The active OTP object for the given user and reason.

  **Raises:**
  - `OTPDoesNotExists`: If no active OTP exists for the given user and reason.
  - `OTPException`: If multiple active OTPs exist for the given user and reason.

- `get_or_create_otp(user: User, reason: ReasonOptions, digits: int = 4, lifetime: int = OTP_LIFETIME, check_expiration: bool = True) -> tuple[OTP, bool]`
  Retrieves an existing OTP or creates a new one if none is found. Expired OTPs are invalidated before generating a new OTP if `check_expiration` is enabled.

  **Arguments:**
  - `user`: The user instance for which the OTP is being generated.
  - `reason`: The reason for OTP generation (e.g., login or password reset).
  - `digits`: The number of digits in the generated OTP (default is 4).
  - `lifetime`: The lifetime of the OTP in seconds (default is `OTP_LIFETIME`).
  - `check_expiration`: A flag indicating whether to check and expire old OTPs (default is `True`).

  **Returns:**
  - `OTP`: The OTP instance.
  - `created`: A boolean indicating whether the OTP was newly created.

  **Example:**
  
  .. code-block:: python

      user = User.objects.get(username="testuser")
      otp, created = otp_service.get_or_create_otp(user, ReasonOptions.LOGIN)
      if created:
          print(f"New OTP generated: {otp.token}")
      else:
          print(f"Existing active OTP: {otp.token}")

- `verify(user: User, reason: ReasonOptions, token: str) -> None`
  Verifies if a given OTP token is valid for a user and reason. If valid, the OTP's state is updated to CONSUMED.

  **Arguments:**
  - `user`: The user instance for whom the token is being verified.
  - `reason`: The reason for which the OTP was generated.
  - `token`: The OTP token provided by the user for validation.

  **Raises:**
  - `InvalidTokenException`: If the token is invalid or no active OTP is found.

  **Example:**
  .. code-block:: python

      user = User.objects.get(username="testuser")
      otp_service.verify(user, ReasonOptions.LOGIN, "123456")

- `expire_old_otp(user: User, reason: ReasonOptions) -> None`
  Expires any old OTPs for a user and reason. Active OTPs are checked for expiration, and if expired, they are marked as EXPIRED.

  **Arguments:**
  - `user`: The user instance for whom old OTPs are to be expired.
  - `reason`: The reason for which old OTPs are to be expired (e.g., login or password reset).

  **Example:**
  .. code-block:: python

      user = User.objects.get(username="testuser")
      otp_service.expire_old_otp(user, ReasonOptions.LOGIN)

Example Usage
^^^^^^^^^^^^^

.. code-block:: python

    from sage_otp.service.otp_service import OTPService
    from sage_otp.helpers.choices import ReasonOptions

    otp_service = OTPService()

    # Retrieve or generate a new OTP
    user = User.objects.get(username="testuser")
    otp, created = otp_service.get_or_create_otp(user, ReasonOptions.LOGIN)

    # Verify the OTP
    otp_service.verify(user, ReasonOptions.LOGIN, "123456")

    # Expire any old OTPs
    otp_service.expire_old_otp(user, ReasonOptions.LOGIN)

