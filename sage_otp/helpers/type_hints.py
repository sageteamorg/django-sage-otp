import hmac
from typing import Callable, NewType

HashAlgorithm = Callable[[bytes, bytes], hmac.HMAC]
Seconds = NewType("Seconds", int)
Minutes = NewType("Minutes", int)
