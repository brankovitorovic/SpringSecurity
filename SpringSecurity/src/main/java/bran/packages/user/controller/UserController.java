package bran.packages.user.controller;

import java.util.List;
import java.util.UUID;

import javax.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import bran.packages.user.dto.UserDTO;
import bran.packages.user.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

	private final UserService userService;

	@PreAuthorize("hasAnyRole('ADMIN', 'PROVIDER')")
	@DeleteMapping("/delete/existingId={existingId}")
	public ResponseEntity<?> deleteById(@PathVariable UUID existingId) {
		userService.deleteById(existingId);
		return new ResponseEntity<>(HttpStatus.OK);
	}

	@PostMapping("/save")
	public ResponseEntity<UserDTO> save(@Valid @RequestBody UserDTO request) {
		return new ResponseEntity<>(userService.save(request), HttpStatus.OK);
	}

	@PreAuthorize("hasAnyRole('ADMIN', 'PROVIDER')")
	@PutMapping("/update/existingId={existingId}")
	public ResponseEntity<UserDTO> update(@PathVariable UUID existingId, @Valid @RequestBody UserDTO request) {
		return new ResponseEntity<>(userService.update(existingId, request), HttpStatus.OK);
	}

	@PreAuthorize("hasAnyRole('ADMIN', 'PROVIDER')")
	@GetMapping("/id={id}")
	public ResponseEntity<UserDTO> findById(@PathVariable UUID id) {
		return new ResponseEntity<>(userService.findByFrontUUID(id), HttpStatus.OK);
	}

	@PreAuthorize("hasAnyRole('ADMIN', 'PROVIDER')")
	@GetMapping("/username={username}")
	public ResponseEntity<UserDTO> findByUsername(@PathVariable String username) {
		return new ResponseEntity<>(userService.findByUsername(username), HttpStatus.OK);
	}

	@PreAuthorize("hasAnyRole('ADMIN', 'PROVIDER')")
	@GetMapping("/all")
	public ResponseEntity<List<UserDTO>> findAll() {
		return new ResponseEntity<>(userService.findAll(), HttpStatus.OK);
	}

}
