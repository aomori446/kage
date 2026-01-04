package shadowsocks

import (
	"bytes"
	crand "crypto/rand"
	"testing"
	
	"github.com/aomori446/kage/config"
)

func TestCipher_Seal(t *testing.T) {
	key := make([]byte, 32)
	_, err := crand.Read(key)
	if err != nil {
		t.Fatal(err)
	}
	
	salt := make([]byte, 32)
	_, err = crand.Read(salt)
	if err != nil {
		t.Fatal(err)
	}
	
	enCipher, err := NewCipher(key, salt, config.CipherMethod2022blake3aes256gcm)
	if err != nil {
		t.Fatal(err)
	}
	
	deCipher, err := NewCipher(key, salt, config.CipherMethod2022blake3aes256gcm)
	if err != nil {
		t.Fatal(err)
	}
	
	t.Run("normal seal and open", func(t *testing.T) {
		for range 1000 {
			data := make([]byte, 1000)
			_, err := crand.Read(data)
			if err != nil {
				t.Fatal(err)
			}
			
			ciphertext := enCipher.Seal(nil, data)
			
			plaintext, err := deCipher.Open(nil, ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			
			if !bytes.Equal(data, plaintext) {
				t.Errorf("got %x, want %x", plaintext, data)
			}
		}
	})
	
	t.Run("open error", func(t *testing.T) {
		data := make([]byte, 1000)
		_, err := crand.Read(data)
		if err != nil {
			t.Fatal(err)
		}
		
		enCipher.counter.Count()
		ciphertext := enCipher.Seal(nil, data)
		
		_, err = deCipher.Open(nil, ciphertext)
		if err == nil {
			t.Errorf("got nil, want error")
		}
	})
}

func TestCipher_Seals(t *testing.T) {
	key := make([]byte, 32)
	_, err := crand.Read(key)
	if err != nil {
		t.Fatal(err)
	}
	
	salt := make([]byte, 32)
	_, err = crand.Read(salt)
	if err != nil {
		t.Fatal(err)
	}
	
	enCipher, err := NewCipher(key, salt, config.CipherMethod2022blake3aes256gcm)
	if err != nil {
		t.Fatal(err)
	}
	
	deCipher, err := NewCipher(key, salt, config.CipherMethod2022blake3aes256gcm)
	if err != nil {
		t.Fatal(err)
	}
	
	ciphertext := enCipher.Seals(salt, []byte("hello,"), []byte("world!"))
	
	gotSalt := ciphertext[:len(salt)]
	
	if !bytes.Equal(gotSalt, salt) {
		t.Errorf("got %x, want %x", gotSalt, salt)
	}
	
	partOne, err := deCipher.Open(nil, ciphertext[len(salt):len(salt)+6+enCipher.Overhead()])
	if err != nil {
		t.Fatal(err)
	}
	
	if !bytes.Equal(partOne, []byte("hello,")) {
		t.Errorf("got %x, want %x", partOne, []byte("hello,"))
	}
	
	partTwo, err := deCipher.Open(nil, ciphertext[len(salt)+6+enCipher.Overhead():])
	if err != nil {
		t.Fatal(err)
	}
	
	if !bytes.Equal(partTwo, []byte("world!")) {
		t.Errorf("got %x, want %x", partTwo, []byte("world!"))
	}
}
