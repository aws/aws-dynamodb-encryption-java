package com.amazonaws.examples.mapper;

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DoNotTouch;

import java.util.Date;

public class DateRangedDoNotTouch {
  private Date start;
  private Date end;

  public DateRangedDoNotTouch(DateRange dateRange) {
    this.start = dateRange.getStart();
    this.end = dateRange.getEnd();
  }

  public DateRangedDoNotTouch() {};

  @DoNotTouch
  public Date getStart() { return start; }
  public void setStart(Date start) { this.start = start; }

  @DoNotTouch
  public Date getEnd() { return end; }
  public void setEnd(Date end) { this.end = end; }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    DateRangedDoNotTouch other = (DateRangedDoNotTouch) obj;
    if (start == null) {
      if (other.start != null) return false;
    } else if (!start.equals(other.start)) return false;
    if (end == null) {
      if (other.end != null) return false;
    } else if (!end.equals(other.end)) return false;
    return true;
  }

  @Override
  public String toString() {
    return "DateRangedDoNotTouch [start=" + start + ", end=" + end +"]";
  }
}
