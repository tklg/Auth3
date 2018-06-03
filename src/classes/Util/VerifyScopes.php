<?php

namespace Auth3\Util;

class VerifyScopes {
	public static function verify($required, array $given) {
		if (!is_array($required)) $required = [$required];
		if (in_array('user.all', $given)) return true;
		return !array_diff($given, $required);
	}
}