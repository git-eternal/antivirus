#pragma once

template <typename T> class Singleton
{
protected:
	Singleton() noexcept = default; 

private:
	Singleton(const Singleton&) = delete;
	Singleton(Singleton&&) = delete;
	Singleton& operator=(const Singleton&) = delete;
	Singleton& operator=(Singleton&&) = delete;

public:
	virtual ~Singleton() noexcept = default;

	static T& GetInstance() noexcept(std::is_nothrow_constructible<T>::value)
	{
		static T instance; return instance;
	}
};
