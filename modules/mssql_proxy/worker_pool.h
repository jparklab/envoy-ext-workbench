#pragma once

// A fixed set of threads running tasks in order of arrival, for work that may
// block (Kerberos steps that ask the KDC) and so can't run on Envoy's event
// loops. No Envoy dependency.

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

namespace MssqlProxy {

class WorkerPool {
public:
  explicit WorkerPool(size_t threads) {
    for (size_t i = 0; i < threads; ++i) {
      threads_.emplace_back([this] { run(); });
    }
  }

  // Waits for the running tasks; queued ones are dropped.
  ~WorkerPool() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      stopping_ = true;
      queue_.clear();
    }
    ready_.notify_all();
    for (std::thread& t : threads_) {
      t.join();
    }
  }

  WorkerPool(const WorkerPool&) = delete;
  WorkerPool& operator=(const WorkerPool&) = delete;

  void post(std::function<void()> task) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (stopping_) {
        return;
      }
      queue_.push_back(std::move(task));
    }
    ready_.notify_one();
  }

private:
  void run() {
    while (true) {
      std::function<void()> task;
      {
        std::unique_lock<std::mutex> lock(mutex_);
        ready_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
        if (stopping_) {
          return;
        }
        task = std::move(queue_.front());
        queue_.pop_front();
      }
      task();
    }
  }

  std::mutex mutex_;
  std::condition_variable ready_;
  std::deque<std::function<void()>> queue_;
  bool stopping_ = false;
  std::vector<std::thread> threads_;
};

} // namespace MssqlProxy
