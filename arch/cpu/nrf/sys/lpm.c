/*
 * Copyright (C) 2024 Marcel Graber <marcel@clever.design>
 * Copyright (C) 2020 Yago Fontoura do Rosario <yago.rosario@hotmail.com.br>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*---------------------------------------------------------------------------*/
/**
 * \addtogroup nrf
 * @{
 *
 * \addtogroup nrf-sys System drivers
 * @{
 *
 * In lowpoer mode, the RTC needs additional handling to wake up the CPU and
 * run the rtimer / etimer code. This is done in soc-rtc.c. Therefore, colck-arch.c
 * only needs to handle the software clock.
 *
 * \file
 *         Software clock implementation for the nRF.
 *
 * \author
 *         Marcel Graber <marcel@clever.design> (lowpower mode)
 *         Yago Fontoura do Rosario <yago.rosario@hotmail.com.br>
 *
 */
/*---------------------------------------------------------------------------*/
#include "lpm.h"
#include "clock.h"
#include "contiki.h"
#include "etimer.h"
#include "gpio-hal-arch.h"
#include "nrf-def.h"
#include "rtimer-arch.h"
#include "rtimer.h"
#include "soc-rtc.h"
#include "sys/energest.h"
#include "sys/process.h"
#include "nrfx_clock.h"

#include "hal/nrf_timer.h"

#include <stdbool.h>
#include <stdint.h>

/*---------------------------------------------------------------------------*/
/*
 * Don't consider deep sleep mode if the next RTC event is scheduled to fire
 * in less than STANDBY_MIN_DURATION rtimer ticks
 */
#define STANDBY_MIN_DURATION  US_TO_RTIMERTICKS(20000) /* 20.0 ms */

/* Wake up this much time earlier before the next rtimer */
/* needed for HFXO power-up and debonce time             */
#define SLEEP_GUARD_TIME      US_TO_RTIMERTICKS(1500) /* 1.5 ms */

/* Maximum allowed sleep-time, must be shorter than watchdog timeout */
#define MAX_SLEEP_TIME        RTIMER_SECOND

/* Minimal safe sleep-time */
#define MIN_SAFE_SCHEDULE     US_TO_RTIMERTICKS(10000) /* 10.0 ms */
/*---------------------------------------------------------------------------*/
/* Prototype of a function in clock.c. Called every time we come out of DS */
void clock_update(void);
/*---------------------------------------------------------------------------*/
/* #include "gpio-hal-arch.h" */
/*   gpio_hal_arch_set_pin(DEBUG1_PORT, DEBUG1_PIN); \ */
#define assert_wfi()                                                           \
  do {                                                                         \
    __asm("wfi" ::);                                                           \
  } while (0)
/*---------------------------------------------------------------------------*/
/*
 * Notify all modules that we're back on and rely on them to restore clocks
 * and power domains as required.
 */
static void
wake_up(void)
{

  ENERGEST_SWITCH(ENERGEST_TYPE_DEEP_LPM, ENERGEST_TYPE_CPU);

  watchdog_periodic();

  /*
   * In LowPower Mode, HFCLK is used by the IEEE 802.15.4 radio.
   * and NRF_TIMER0 is used in the nrf-ieee-driver-arch.c
   * In non-LowPower Mode, HFCLK is also used for the RTIMER
   */
  nrfx_clock_hfclk_start();
  nrf_timer_task_trigger(NRF_TIMER0, NRF_TIMER_TASK_START);
}
/*---------------------------------------------------------------------------*/
static uint8_t
check_next_rtimer(rtimer_clock_t now, rtimer_clock_t *next_rtimer, bool *next_rtimer_set)
{
  uint8_t max_pm = LPM_MODE_MAX_SUPPORTED;

  if(rtimer_arch_next()) {
    *next_rtimer_set = true;

    /* find out the timer of the next rtimer interrupt */
    *next_rtimer = rtimer_arch_next();

    if(RTIMER_CLOCK_LT(*next_rtimer, now + 2)) {
      max_pm = MIN(max_pm, LPM_MODE_AWAKE);
    } else if(RTIMER_CLOCK_LT(*next_rtimer, now + STANDBY_MIN_DURATION)) {
      max_pm = MIN(max_pm, LPM_MODE_SLEEP);
    }
  } else {
    *next_rtimer_set = false;
  }

  return max_pm;
}
/*---------------------------------------------------------------------------*/
static uint8_t
check_next_etimer(rtimer_clock_t now, rtimer_clock_t *next_etimer, bool *next_etimer_set)
{
  uint8_t max_pm = LPM_MODE_MAX_SUPPORTED;

  *next_etimer_set = false;

  /* Find out the time of the next etimer */
  if (etimer_pending()) {
    clock_time_t next = etimer_next_expiration_time();
    *next_etimer_set = true;
    *next_etimer = next * (RTIMER_SECOND / CLOCK_SECOND);
    if (RTIMER_CLOCK_LT(*next_etimer, now + STANDBY_MIN_DURATION)) {
      max_pm = MIN(max_pm, LPM_MODE_SLEEP);
    }
  }

  return max_pm;
}
/*---------------------------------------------------------------------------*/
static uint8_t
setup_sleep_mode(void)
{
  uint8_t max_pm = LPM_MODE_MAX_SUPPORTED;
  uint8_t pm;

  rtimer_clock_t now;
  rtimer_clock_t trigger_etimer = 0;
  rtimer_clock_t next_rtimer = 0;
  rtimer_clock_t next_etimer = 0;
  bool next_rtimer_set = false;
  bool next_etimer_set = false;

  /* Check if any events fired before we turned interrupts off. If so, abort */
  if(LPM_MODE_MAX_SUPPORTED == LPM_MODE_AWAKE || process_nevents()) {
    return LPM_MODE_AWAKE;
  }

  now = RTIMER_NOW();
  pm = check_next_rtimer(now, &next_rtimer, &next_rtimer_set);
  if(pm < max_pm) {
    max_pm = pm;
  }
  pm = check_next_etimer(now, &next_etimer, &next_etimer_set);
  if(pm < max_pm) {
    max_pm = pm;
  }
  trigger_etimer = RTIMER_CLOCK_MAX;
  if(max_pm == LPM_MODE_SLEEP) {
    /* In sleep mode, HFXO is powered up, therefore we do  not have
     * to wakeup earlier to powering up the HFXO */
    if(next_etimer_set) {
      /* Schedule the next system wakeup due to etimer */
      if(RTIMER_CLOCK_LT(next_etimer, now + MIN_SAFE_SCHEDULE)) {
        /* Too soon in future, keep the system awake */
      } else if(RTIMER_CLOCK_LT(now + MAX_SLEEP_TIME, next_etimer)) {
        /* Too far in future, use MAX_SLEEP_TIME instead */
        trigger_etimer = now + MAX_SLEEP_TIME;
      } else {
        trigger_etimer = next_etimer;
      }
    } else {
      /* No etimers set. Since by default the CH1 RTC fires once every clock tick,
       * need to explicitly schedule a wakeup in the future to save energy.
       * But do not stay in this mode for too long, otherwise watchdog will be trigerred. */
      trigger_etimer = next_etimer;
    }
  } else if(max_pm == LPM_MODE_DEEP_SLEEP) {
    /* Watchdog is not enabled, so deep sleep can continue an arbitrary long time.
     * On the other hand, when we have to start again the system, it takes a while
     * till the HFXO is stable and the system is ready to run. Therefore, we have
     * early wakeup before the next rtimer should be scheduled. */
    if(next_rtimer_set) {
      if(!next_etimer_set || RTIMER_CLOCK_LT(next_rtimer - SLEEP_GUARD_TIME, next_etimer)) {
        /* schedule a wakeup briefly before the next rtimer to wake up the system */
        trigger_etimer = next_rtimer - SLEEP_GUARD_TIME;
      }
    }

    if(next_etimer_set) {
      /* Schedule the next system wakeup due to etimer.
       * No need to compare the `next_etimer` to `now` here as this branch
       * is only entered when there's sufficient time for deep sleeping.
       * keep the trigger_etimer from the step before, if it is earlier */
      if (RTIMER_CLOCK_LT(next_etimer, trigger_etimer)) {
        trigger_etimer = next_etimer;
      }
    }
  }
  if (trigger_etimer != RTIMER_CLOCK_MAX) {
    if (trigger_etimer > now) {
      soc_rtc_schedule_one_shot(SOC_RTC_SYSTEM_CH, trigger_etimer);
    }
  }

  return max_pm;
}
/*---------------------------------------------------------------------------*/
void
lpm_sleep(void)
{
  ENERGEST_SWITCH(ENERGEST_TYPE_CPU, ENERGEST_TYPE_LPM);

  assert_wfi();

  /* Kick watchdog to ensure a full interval is available after sleep */
  watchdog_periodic();

  ENERGEST_SWITCH(ENERGEST_TYPE_LPM, ENERGEST_TYPE_CPU);
}
/*---------------------------------------------------------------------------*/
static void
deep_sleep(void)
{
  /* Pat the dog: We don't want it to shout right after we wake up */
  watchdog_periodic();

  /* In LowPower Mode, HFCLK is used by the IEEE 802.15.4 radio.
   * and NRF_TIMER0 in nrf-ieee-driver-arch.c
   */
  nrfx_clock_hfclk_stop();
  nrf_timer_task_trigger(NRF_TIMER0, NRF_TIMER_TASK_SHUTDOWN);
  ENERGEST_SWITCH(ENERGEST_TYPE_CPU, ENERGEST_TYPE_DEEP_LPM);

  /* Deep Sleep */
  assert_wfi();

  /*
   * When we reach here, some interrupt woke us up. The global interrupt
   * flag is off, hence we have a chance to run things here. We will wake up
   * the chip properly, and then we will enable the global interrupt without
   * unpending events so the handlers can fire
   */
  wake_up();
}
/*---------------------------------------------------------------------------*/
void
lpm_drop()
{
  uint8_t max_pm;
  int abort;
  int_master_status_t status;

  status = critical_enter();
  abort = process_nevents();

  if (!abort) {
    max_pm = setup_sleep_mode();
    /* Drop */
    if (max_pm == LPM_MODE_SLEEP) {
      lpm_sleep();
    } else if (max_pm == LPM_MODE_DEEP_SLEEP) {
      deep_sleep();
    }
  }
  critical_exit(status);
}
/*---------------------------------------------------------------------------*/
/** @} */
/** @} */