package bran.packages.user.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import bran.packages.user.entity.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long>{

    Optional<User> findByUsername(String username);

	void deleteByFrontId(UUID existingId);
    
    
	
}
