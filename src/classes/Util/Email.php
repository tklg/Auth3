<?php

namespace Auth3\Util;

class Email {
	protected $config;
	protected $from;
	protected $to;
	protected $subject;
	protected $text;
	protected $html;
	public function __construct() {
		$this->config = \Auth3\Config::getConfig()['email'];
	}
	public function setText($text) {
		$this->text = $text;
	}
	public function setHtml($html) {
		$this->html = $html;
	}
	public function setFrom($from) {
		$this->from = $from;
	}
	public function setTo($to) {
		$this->to = $to;
	}
	public function setSubject($subject) {
		$this->subject = $subject;
	}
	public function send() {
		foreach (['from', 'to', 'subject'] as $key) {
			if (is_null($this->$key)) throw new \Exception("Missing parameter: " . $key, 1);
		}
		if (is_null($this->text) && is_null($this->html)) throw new \Exception("Must have one or both of (text, html) set.", 1);

		$c = curl_init();

		curl_setopt($c, CURLOPT_SSL_VERIFYHOST, 0);
		curl_setopt($c, CURLOPT_SSL_VERIFYPEER, 0);

		curl_setopt($c, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
		curl_setopt($c, CURLOPT_USERPWD, 'api:'.$this->config['api_key']);
		curl_setopt($c, CURLOPT_RETURNTRANSFER, 1);
	    curl_setopt($c, CURLOPT_CUSTOMREQUEST, 'POST');
	    curl_setopt($c, CURLOPT_URL, $this->config['api_base_url'].'/messages');

	    curl_setopt($c, CURLOPT_POSTFIELDS, [
	    	'from' => $this->from,
	        'to' => $this->to,
	        'subject' => $this->subject,
	        'html' => $this->html,
	        'text' => $this->text
	    ]);

	    $result = curl_exec($c);
	    $info = curl_getinfo($c);


	    if ($info['http_code'] != 200) {
	        throw new \Exception("Could not send email (" . $info['http_code'] . "): " . curl_error($c), 1);
	    }

	    curl_close($c);
	    return $result;
	}
}