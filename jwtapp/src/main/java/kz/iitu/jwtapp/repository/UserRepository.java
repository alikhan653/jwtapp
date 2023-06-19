package kz.iitu.jwtapp.repository;

import kz.iitu.jwtapp.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String name);
}
