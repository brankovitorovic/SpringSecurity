package bran.packages.user.service;

import java.util.List;
import java.util.UUID;

import javax.transaction.Transactional;

import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;

import bran.packages.user.dto.UserDTO;
import bran.packages.user.dto.UserRoleDTO;
import bran.packages.user.entity.User;
import bran.packages.user.exception.InvalidUserInfoException;
import bran.packages.user.exception.UserNotFoundException;
import bran.packages.user.mapper.UserMapper;
import bran.packages.user.repository.UserRepository;
import bran.packages.user.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

	private final UserRepository userRepository;

	private final UserRoleRepository userRoleRepository;

	private final UserMapper mapper;

	@Transactional
	public void deleteById(UUID existingId) {
		if (userNotFound(existingId))
			throw new UserNotFoundException(String.format("User with id: %d wasn't found!", existingId));

		userRepository.deleteByFrontId(existingId);
	}

	private boolean userNotFound(UUID existingId) {
		return findAll().stream().filter(s -> s.getFrontId().equals(existingId)).findFirst().isEmpty();
	}

	@Transactional
	public UserDTO save(UserDTO request) {
		if (usernameExists(request))
			throw new InvalidUserInfoException(
					String.format("User with username: %s already exists!", request.getUsername()));

		if (invalidUserRoles(request))
			throw new InvalidUserInfoException("Invalid user roles!");

		request.setPassword(hashPassword(request.getPassword()));

		request.setFrontId(UUID.randomUUID());

		User user = userRepository.save(mapper.fromDTO(request));

		return mapper.toDTO(user);
	}

	private boolean usernameExists(UserDTO user) {
		return userRepository.findByUsername(user.getUsername()).isPresent();
	}

	private boolean invalidUserRoles(UserDTO request) {
		return request.getRoles().stream().anyMatch(this::roleNotFound);
	}

	private boolean roleNotFound(UserRoleDTO role) {
		return userRoleRepository.findById(role.getId()).isEmpty();
	}

	private String hashPassword(String plainText) {
		return BCrypt.hashpw(plainText, BCrypt.gensalt());
	}

	@Transactional
	public UserDTO update(UUID existingId, UserDTO request) {

		if (usernameExists(request))
			throw new InvalidUserInfoException(
					String.format("User with username: %s already exists!", request.getUsername()));
		if (invalidUserRoles(request))
			throw new InvalidUserInfoException("Invalid user roles!");

		if (request.isPasswordPlain())
			request.setPassword(hashPassword(request.getPassword()));

		request.setFrontId(existingId);
		User user = userRepository.save(mapper.fromDTO(request));

		return mapper.toDTO(user);
	}

	public UserDTO findByUsername(String username) {
		return userRepository.findByUsername(username).map(mapper::toDTO).orElseThrow(
				() -> new UserNotFoundException(String.format("User with username: %s wasn't found!", username)));
	}

	public UserDTO findByFrontUUID(UUID existingId) {
		return findAll().stream().filter(s -> s.getFrontId().equals(existingId)).findFirst().orElseThrow(
				() -> new UserNotFoundException(String.format("User with id: %s wasn't found!", existingId)));
	}

	public List<UserDTO> findAll() {
		return mapper.toDTOList(userRepository.findAll());
	}

}
