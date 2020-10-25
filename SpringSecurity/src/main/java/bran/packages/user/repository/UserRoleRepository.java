package bran.packages.user.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import bran.packages.user.entity.UserRole;

@Repository
public interface UserRoleRepository extends JpaRepository<UserRole,Long>{

    Optional<UserRole> findByName(String name);

	
}
