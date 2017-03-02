function randomNumber(count) {
  var cryptoObj = window.crypto || window.msCrypto;
  var rand = new Uint32Array(1);
  var skip = 0x7fffffff - 0x7fffffff % count;
  var result;

  if (((count - 1) & count) === 0) {
	cryptoObj.getRandomValues(rand);
	return rand[0] & (count - 1);
  }

  do {
	cryptoObj.getRandomValues(rand)
	result = rand[0] & 0x7fffffff;
  } while (result >= skip);

  return result % count;
}

function generateRandomName() {
	var adjective_index = randomNumber(adjectives.length);
	var noun_index = randomNumber(nouns.length);
	var generated_name = adjectives[adjective_index] + "-" + nouns[noun_index];
	document.getElementById("register_name").setAttribute("value", generated_name);
}
